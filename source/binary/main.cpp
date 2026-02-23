#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/Program.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/CodeGen.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Analysis/CGSCCPassManager.h>
#include <llvm/Analysis/LoopAnalysisManager.h>
#include <llvm/Passes/PassBuilder.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/TraceLifter.h>
#include <remill/BC/Util.h>
#include <remill/BC/Optimizer.h>

#include <queue>
#include <array>
#include <cstdint>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <llvm/ADT/SmallString.h>
#include <llvm/Support/Path.h>

#include <shared/io.hpp>
#include <shared/pe_mapper.hpp>

namespace levo
{
    // -----------------------------------------------------------------------------
    // CFG types (from Ghidra ExportCFG.java output)
    // -----------------------------------------------------------------------------
    struct CfgBlock
    {
        uint64_t start = 0;
        uint64_t end = 0;
    };

    struct CfgFunction
    {
        std::string name;
        uint64_t address = 0;
        std::vector<CfgBlock> blocks;
        std::vector<std::string> indirect_call_sites;
    };

    struct Cfg
    {
        std::string program_name;
        uint64_t image_base = 0;
        std::vector<CfgFunction> functions;
    };

    struct PeSection
    {
        uint32_t virtual_address = 0;
        uint32_t virtual_size = 0;
        uint32_t pointer_to_raw_data = 0;
        uint32_t size_of_raw_data = 0;
    };

    namespace
    {
        std::string format_hex_address(uint64_t addr)
        {
            std::array<char, 24> hex_buf{};
            snprintf(hex_buf.data(), hex_buf.size(), "0x%" PRIx64, addr);
            return hex_buf.data();
        }

        uint64_t parse_hex_address(const std::string& s)
        {
            if (s.size() >= 2 && (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')))
            {
                return std::stoull(s.substr(2), nullptr, 16);
            }
            return std::stoull(s, nullptr, 16);
        }

        std::string get_string(const llvm::json::Object* obj, const char* key, const char* default_val = "0")
        {
            if (!obj)
            {
                return default_val;
            }
            if (auto s = obj->getString(key))
            {
                return s->str();
            }
            return default_val;
        }

        Cfg load_cfg(const std::string& path)
        {
            std::ifstream f(path);
            if (!f)
            {
                throw std::runtime_error("Cannot open CFG file: " + path);
            }
            std::stringstream buf;
            buf << f.rdbuf();
            llvm::Expected<llvm::json::Value> E = llvm::json::parse(buf.str());
            if (!E)
            {
                throw std::runtime_error("Invalid JSON: " + toString(E.takeError()));
            }
            llvm::json::Object* root = E->getAsObject();
            if (!root)
            {
                throw std::runtime_error("CFG root is not a JSON object");
            }

            Cfg cfg;
            cfg.program_name = get_string(root, "program_name", "");
            cfg.image_base = parse_hex_address(get_string(root, "image_base", "0"));

            if (llvm::json::Array* funcs = root->getArray("functions"))
            {
                for (const llvm::json::Value& v : *funcs)
                {
                    const auto* func = v.getAsObject();
                    if (!func)
                    {
                        continue;
                    }
                    CfgFunction cf;
                    cf.name = get_string(func, "name", "");
                    cf.address = parse_hex_address(get_string(func, "address", "0"));
                    if (const auto* blocks = func->getArray("blocks"))
                    {
                        for (const llvm::json::Value& bv : *blocks)
                        {
                            if (const auto* block = bv.getAsObject())
                            {
                                CfgBlock b;
                                b.start = parse_hex_address(get_string(block, "start", "0"));
                                b.end = parse_hex_address(get_string(block, "end", "0"));
                                cf.blocks.push_back(b);
                            }
                        }
                    }
                    if (const auto* sites = func->getArray("indirect_call_sites"))
                    {
                        for (const llvm::json::Value& av : *sites)
                        {
                            if (auto s = av.getAsString())
                            {
                                cf.indirect_call_sites.push_back(s->str());
                            }
                        }
                    }
                    cfg.functions.push_back(std::move(cf));
                }
            }
            return cfg;
        }

        std::vector<uint8_t> load_binary(const std::filesystem::path& path)
        {
            std::vector<uint8_t> data{};
            if (!read_file(path, data))
            {
                throw std::runtime_error("Failed to read binary: " + path.string());
            }

            return data;
        }

        void OptimizeModule(llvm::Module& M, const llvm::OptimizationLevel optimizationLevel)
        {
            llvm::LoopAnalysisManager LAM;
            llvm::FunctionAnalysisManager FAM;
            llvm::CGSCCAnalysisManager CGAM;
            llvm::ModuleAnalysisManager MAM;

            llvm::PassBuilder PB;

            PB.registerModuleAnalyses(MAM);
            PB.registerCGSCCAnalyses(CGAM);
            PB.registerFunctionAnalyses(FAM);
            PB.registerLoopAnalyses(LAM);
            PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

            auto MPM = PB.buildPerModuleDefaultPipeline(optimizationLevel);

            MPM.run(M, MAM);
        }

        // Emit object file from Module using LLVM TargetMachine (in-process, no llc).
        bool emit_object_file(llvm::Module& module, const std::string& obj_path)
        {
            std::string error;
            const llvm::Target* target = llvm::TargetRegistry::lookupTarget(module.getTargetTriple(), error);
            if (!target)
            {
                llvm::errs() << "TargetRegistry::lookupTarget failed: " << error << "\n";
                return false;
            }
            llvm::TargetOptions opt;
            std::unique_ptr<llvm::TargetMachine> tm(target->createTargetMachine(module.getTargetTriple(), "generic", "", opt, std::nullopt,
                                                                                std::nullopt, llvm::CodeGenOptLevel::Default, true));
            if (!tm)
            {
                llvm::errs() << "createTargetMachine failed\n";
                return false;
            }
            module.setDataLayout(tm->createDataLayout());

            std::error_code ec;
            llvm::raw_fd_ostream dest(obj_path, ec, llvm::sys::fs::OF_None);
            if (ec)
            {
                llvm::errs() << "Cannot open output object: " << ec.message() << "\n";
                return false;
            }
            llvm::legacy::PassManager pm;
            if (tm->addPassesToEmitFile(pm, dest, nullptr, llvm::CodeGenFileType::ObjectFile))
            {
                llvm::errs() << "Target does not support object emission\n";
                return false;
            }
            pm.run(module);
            dest.flush();
            llvm::outs() << "Emitted object " << obj_path << "\n";
            return true;
        }

        // Link object to executable by invoking lld (lld-link on Windows).
        // Uses LLVM_TOOLS_DIR if set, otherwise relies on PATH.
        bool link_executable(const std::string& obj_path, const std::string& exe_path, const std::filesystem::path& base_path)
        {
            std::string lld_path;
            std::string lib_prefix;
            std::string lib_suffix;
#if defined(LLVM_TOOLS_DIR)
            llvm::SmallString<256> llvm_tools(LLVM_TOOLS_DIR);
            llvm::sys::path::native(llvm_tools);
            std::string tools_dir(llvm_tools.str());
            if (!tools_dir.empty() && tools_dir.back() != '/' && tools_dir.back() != '\\')
            {
                tools_dir += llvm::sys::path::get_separator().str();
            }
#if defined(_WIN32)
            lld_path = tools_dir + "lld-link.exe";
            lib_prefix = "";
            lib_suffix = ".lib";
#else
            lld_path = tools_dir + "ld.lld";
            lib_prefix = "lib";
            lib_suffix = ".a";
#endif
#else
#if defined(_WIN32)
            lld_path = "lld-link";
#else
            lld_path = "ld.lld";
#endif
#endif

            const std::vector<std::filesystem::path> libraries = {
                base_path / ".." / "runtime" / (lib_prefix + "runtime" + lib_suffix),
                base_path / ".." / "shared" / (lib_prefix + "shared" + lib_suffix),
            };

#if defined(_WIN32)
            std::vector<std::string> link_args = {
                "lld-link", "/DEBUG", "/out:" + exe_path, "/SUBSYSTEM:CONSOLE", obj_path,
            };
#else
            std::vector<std::string> link_args = {"ld.lld", "-o", exe_path, obj_path, "-lc"};
#endif

            for (const auto& library : libraries)
            {
                link_args.push_back(library.string());
            }

            std::vector<llvm::StringRef> link_refs(link_args.begin(), link_args.end());
            std::string err_msg;
            int ret = llvm::sys::ExecuteAndWait(lld_path, link_refs, std::nullopt, {}, 0, 0, &err_msg);
            if (ret != 0)
            {
                llvm::errs() << "Link failed: " << err_msg << "\n";
                return false;
            }
            llvm::outs() << "Linked " << exe_path << "\n";
            return true;
        }

        // Emit object from Module (in-process) then invoke lld to link.
        bool compile_and_link(llvm::Module& dest_module, const std::string& output_path, const std::filesystem::path& base_path)
        {
            std::string base = output_path;
            const size_t dot = output_path.rfind('.');
            if (dot != std::string::npos && dot > 0)
            {
                base.resize(dot);
            }
#if defined(_WIN32)
            std::string obj_path = base + ".obj";
            std::string exe_path = base + "_transpiled.exe";
#else
            std::string obj_path = base + ".o";
            std::string exe_path = base + "_transpiled";
#endif
            if (!emit_object_file(dest_module, obj_path))
            {
                return false;
            }
            if (!link_executable(obj_path, exe_path, base_path))
            {
                return false;
            }
            return true;
        }

        // -----------------------------------------------------------------------------
        // TraceManager: provides bytes from image and stores lifted trace decls/defs.
        // Each basic block is lifted as its own function; blocks tail-call to successors.
        // -----------------------------------------------------------------------------
        class CfgTraceManager : public remill::TraceManager
        {
          public:
            CfgTraceManager(const remill::Arch* arch, llvm::Module* module, const std::vector<uint8_t>& image, uint64_t image_base,
                            const Cfg& cfg)
                : arch_(arch),
                  module_(module),
                  image_(image),
                  image_base_(image_base)
            {
                for (const auto& f : cfg.functions)
                {
                    for (const auto& block : f.blocks)
                    {
                        block_bounds_[block.start] = block.end;
                    }
                }
            }

            std::string TraceName(uint64_t addr) override
            {
                auto it = trace_names_.find(addr);
                if (it != trace_names_.end())
                {
                    return it->second;
                }

                return "block_" + format_hex_address(addr);
            }

            void SetLiftedTraceDefinition(uint64_t addr, llvm::Function* lifted_func) override
            {
                std::lock_guard<std::mutex> lock(mu_);
                traces_[addr] = lifted_func;
            }

            llvm::Function* GetLiftedTraceDeclaration(uint64_t addr) override
            {
                std::lock_guard<std::mutex> lock(mu_);
                const auto block_address = GetBasicBlockStart(addr);

                // Only return a declaration for block-start addresses. For mid-block
                // addresses (e.g. fall-through), return nullptr so the TraceLifter
                // decodes the instruction and continues the current trace instead of
                // emitting a tail call to "this address as trace head".
                if (addr != block_address)
                {
                    return nullptr;
                }

                auto it = traces_.find(block_address);
                if (it != traces_.end())
                {
                    return it->second;
                }

                const auto name = TraceName(block_address);
                auto* decl = arch_->DeclareLiftedFunction(name, module_);
                traces_[block_address] = decl;
                lift_queue_.push(block_address);
                return decl;
            }

            llvm::Function* GetLiftedTraceDefinition(uint64_t addr) override
            {
                std::lock_guard<std::mutex> lock(mu_);
                const auto block_address = GetBasicBlockStart(addr);
                auto it = traces_.find(block_address);
                if (it != traces_.end())
                {
                    if (!it->second->isDeclaration())
                    {
                        return it->second;
                    }
                }
                return nullptr;
            }

            bool TryReadExecutableByte(uint64_t addr, uint8_t* byte) override
            {
                if (!GetBasicBlockBounds(addr))
                {
                    return false;
                }

                if (addr < image_base_)
                {
                    return false;
                }

                const auto rva = static_cast<size_t>(addr - image_base_);
                if (rva >= image_.size())
                {
                    return false;
                }

                *byte = image_[rva];
                return true;
            }

            const std::unordered_map<uint64_t, llvm::Function*>& GetLiftedTraces() const
            {
                return traces_;
            }

            std::optional<uint64_t> GetNextLiftAddress()
            {
                std::lock_guard<std::mutex> lock(mu_);
                if (lift_queue_.empty())
                {
                    return std::nullopt;
                }

                const auto result = lift_queue_.front();
                lift_queue_.pop();
                return result;
            }

            uint64_t GetBasicBlockStart(uint64_t addr) const
            {
                const auto bounds = GetBasicBlockBounds(addr);
                if (!bounds)
                {
                    return addr;
                }

                return bounds->first;
            }

            std::optional<std::pair<uint64_t, uint64_t>> GetBasicBlockBounds(uint64_t addr) const
            {
                auto it = block_bounds_.upper_bound(addr);
                if (it == block_bounds_.begin())
                {
                    return std::nullopt;
                }

                --it;

                if (addr >= it->first && addr < it->second)
                {
                    return *it;
                }

                return std::nullopt;
            }

          private:
            const remill::Arch* arch_;
            llvm::Module* module_;
            const std::vector<uint8_t>& image_;
            uint64_t image_base_;
            std::unordered_map<uint64_t, std::string> trace_names_;
            std::mutex mu_;
            std::unordered_map<uint64_t, llvm::Function*> traces_;
            std::map<uint64_t, uint64_t> block_bounds_;
            std::queue<uint64_t> lift_queue_;
        };

        int run(int argc, char** argv)
        {
            llvm::InitLLVM init_llvm(argc, argv);
            llvm::InitializeNativeTarget();
            llvm::InitializeNativeTargetAsmPrinter();
            llvm::InitializeAllTargetMCs();

            bool do_compile = false;
            int arg_idx = 1;
            for (; arg_idx < argc && argv[arg_idx] != nullptr; ++arg_idx)
            {
                if (std::string(argv[arg_idx]) == "--compile")
                {
                    do_compile = true;
                    continue;
                }
                break;
            }
            if (argc - arg_idx < 3)
            {
                llvm::errs() << "Usage: " << argv[0] << " [--compile] <cfg.json> <binary> <output.bc>\n"
                             << "  --compile  After writing .bc, emit object (in-process) and link with lld.\n";
                return 1;
            }
            const char* cfg_path = argv[arg_idx];
            const char* binary_path = argv[arg_idx + 1];
            const char* output_path = argv[arg_idx + 2];

            const auto base_path = std::filesystem::path(argv[0]).parent_path();

            Cfg cfg = load_cfg(cfg_path);
            const auto binary_data = load_binary(binary_path);
            const auto architecture = get_pe_architecture(binary_data);
            if (!architecture)
            {
                llvm::errs() << "Failed to get PE architecture\n";
                return 1;
            }

            const auto image = map_pe_file(binary_data);

            llvm::LLVMContext context;

            remill::Arch::ArchPtr arch = remill::Arch::Get(context, "windows", *architecture == pe_architecture::x64 ? "amd64" : "x86");
            if (!arch)
            {
                llvm::errs() << "Failed to get remill arch (windows/amd64)\n";
                return 1;
            }

            // Load arch semantics (required: TraceLifter uses arch->GetInstrinsicTable()
            // which is populated from this module).
            auto module = remill::LoadArchSemantics(arch.get());
            if (!module)
            {
                llvm::errs() << "Failed to load arch semantics (check REMILL_BUILD_SEMANTICS_DIR_*)\n";
                return 1;
            }
            arch->InitFromSemanticsModule(module.get());
            arch->PrepareModule(module.get());

            CfgTraceManager manager(arch.get(), module.get(), image, cfg.image_base, cfg);
            remill::TraceLifter lifter(arch.get(), manager);

            for (const auto& f : cfg.functions)
            {
                for (const auto& block : f.blocks)
                {
                    manager.GetLiftedTraceDeclaration(block.start);
                }
            }

            while (true)
            {
                const auto next_addr = manager.GetNextLiftAddress();
                if (!next_addr)
                {
                    break;
                }

                llvm::outs() << "Lifting block " << format_hex_address(*next_addr) << "\n";

                lifter.Lift(*next_addr);
            }

            remill::OptimizationGuide guide = {};
            remill::OptimizeModule(arch, module, manager.GetLiftedTraces(), guide);

            llvm::Module dest_module("lifted_code", context);
            dest_module.setTargetTriple(module->getTargetTriple());
            arch->PrepareModuleDataLayout(&dest_module);

            std::map<uint64_t, llvm::Function*> final_functions{};

            for (const auto& lifted_entry : manager.GetLiftedTraces())
            {
                remill::MoveFunctionIntoModule(lifted_entry.second, &dest_module);
                final_functions[lifted_entry.first] = dest_module.getFunction(lifted_entry.second->getName());
            }

            dest_module.setTargetTriple(LLVM_HOST_TRIPLE);

            auto* int64_type = llvm::Type::getInt64Ty(context);
            auto* ptr_type = llvm::PointerType::getUnqual(context);
            auto* dispatch_entry_type = llvm::StructType::get(context, {
                                                                           int64_type,
                                                                           ptr_type,
                                                                       });

            std::vector<llvm::Constant*> dispatch_entries;
            dispatch_entries.reserve(final_functions.size());
            for (const auto& final_function : final_functions)
            {
                auto* dispatch_entry =
                    llvm::ConstantStruct::get(dispatch_entry_type, {
                                                                       llvm::ConstantInt::get(int64_type, final_function.first),
                                                                       final_function.second,
                                                                   });
                dispatch_entries.push_back(dispatch_entry);
            }

            auto* null_entry = llvm::ConstantStruct::get(dispatch_entry_type, {
                                                                                  llvm::ConstantInt::get(int64_type, 0),
                                                                                  llvm::ConstantPointerNull::get(ptr_type),
                                                                              });
            dispatch_entries.push_back(null_entry);

            auto* dispatch_array_type = llvm::ArrayType::get(dispatch_entry_type, dispatch_entries.size());
            new llvm::GlobalVariable(dest_module, dispatch_array_type, true, llvm::GlobalValue::ExternalLinkage,
                                     llvm::ConstantArray::get(dispatch_array_type, dispatch_entries), "dispatch_table");

            auto* binary_data_array = llvm::ConstantDataArray::getString(
                context, llvm::StringRef(reinterpret_cast<const char*>(binary_data.data()), binary_data.size()), false);
            new llvm::GlobalVariable(dest_module, binary_data_array->getType(), true, llvm::GlobalValue::ExternalLinkage, binary_data_array,
                                     "binary_data");

            new llvm::GlobalVariable(dest_module, int64_type, true, llvm::GlobalValue::ExternalLinkage,
                                     llvm::ConstantInt::get(int64_type, binary_data.size()), "binary_size");

            new llvm::GlobalVariable(dest_module, int64_type, true, llvm::GlobalValue::ExternalLinkage,
                                     llvm::ConstantInt::get(int64_type, cfg.image_base), "image_base");

            llvm::outs() << "Optimizing module\n";
            OptimizeModule(dest_module, llvm::OptimizationLevel::O3);

            for (auto& func : dest_module)
            {
                func.removeFnAttr(llvm::Attribute::NoUnwind);
                func.setUWTableKind(llvm::UWTableKind::Default);
            }

            std::error_code ec;
            llvm::raw_fd_ostream os(output_path, ec);

            if (ec)
            {
                llvm::errs() << "Cannot open output: " << ec.message() << "\n";
                return 1;
            }

            dest_module.print(os, nullptr);
            llvm::outs() << "Lifted " << cfg.functions.size() << " functions to " << output_path << "\n";

            if (do_compile)
            {
                if (!compile_and_link(dest_module, output_path, base_path))
                {
                    return 1;
                }
            }

            return 0;
        }
    }
}

int main(int argc, char** argv)
{
    try
    {
        return levo::run(argc, argv);
    }
    catch (const std::exception& e)
    {
        llvm::errs() << "Error: " << e.what() << "\n";
    }
}
