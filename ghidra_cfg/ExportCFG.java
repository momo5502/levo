/* ###
 * IP: PUBLIC DOMAIN
 *
 * Export Control Flow Graph (functions, basic blocks, edges, indirect targets)
 * to JSON for use by the remill lifter pipeline. Run as a Ghidra headless
 * postScript after analysis.
 *
 * Usage (headless):
 *   analyzeHeadless /path/to/project ProjectName -import game.exe \
 *     -postScript ExportCFG.java output.json
 *
 * Script args: first argument is the output JSON file path (required in headless).
 */

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.exception.CancelledException;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class ExportCFG extends GhidraScript {

    private static String addrToString(Address addr) {
        return addr == null ? null : "0x" + Long.toHexString(addr.getOffset());
    }

    @Override
    public void run() throws Exception {
        Program program = getCurrentProgram();
        if (program == null) {
            printerr("No current program.");
            return;
        }

        String[] args = getScriptArgs();
        String outputPath = (args != null && args.length > 0) ? args[0] : null;
        if (outputPath == null || outputPath.isEmpty()) {
            printerr("Usage: ExportCFG.java <output.json>");
            return;
        }

        File outFile = new File(outputPath);
        if (outFile.getParentFile() != null) {
            outFile.getParentFile().mkdirs();
        }

        BasicBlockModel blockModel = new BasicBlockModel(program);
        FunctionManager functionManager = program.getFunctionManager();

        CfgOutput output = new CfgOutput();
        output.program_name = program.getDomainFile().getName();
        output.image_base = addrToString(program.getImageBase());
        output.functions = new ArrayList<>();

        Iterator<Function> funcIter = functionManager.getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            if (func.getBody() == null || func.getBody().isEmpty()) continue;

            FunctionCfg fc = new FunctionCfg();
            fc.name = func.getName();
            fc.address = addrToString(func.getEntryPoint());
            fc.blocks = new ArrayList<>();
            fc.edges = new ArrayList<>();
            fc.indirect_call_sites = new ArrayList<>();

            CodeBlockIterator blockIter = blockModel.getCodeBlocksContaining(func.getBody(), getMonitor());
            List<CodeBlock> blocks = new ArrayList<>();
            while (blockIter.hasNext()) {
                try {
                    blocks.add(blockIter.next());
                } catch (CancelledException e) {
                    break;
                }
            }

            for (CodeBlock block : blocks) {
                Block b = new Block();
                b.start = addrToString(block.getFirstStartAddress());
                // end is exclusive (first address after the block)
                b.end = addrToString(block.getMaxAddress().add(1));
                fc.blocks.add(b);
            }

            for (CodeBlock block : blocks) {
                CodeBlockReferenceIterator destIter = block.getDestinations(getMonitor());
                while (destIter.hasNext()) {
                    CodeBlockReference ref;
                    try {
                        ref = destIter.next();
                    } catch (CancelledException e) {
                        break;
                    }
                    FlowType flowType = ref.getFlowType();
                    String edgeType = "branch";
                    if (flowType.isCall()) edgeType = "call";
                    else if (flowType.isFallthrough()) edgeType = "fallthrough";

                    Edge e = new Edge();
                    e.from = addrToString(block.getFirstStartAddress());
                    e.to = addrToString(ref.getDestinationAddress());
                    e.type = edgeType;
                    if (flowType.isComputed()) e.indirect = true;
                    fc.edges.add(e);

                    if (flowType.isComputed() && flowType.isCall()) {
                        fc.indirect_call_sites.add(addrToString(ref.getReferent()));
                    }
                }
            }

            output.functions.add(fc);
        }

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(output);
        Files.write(outFile.toPath(), json.getBytes(StandardCharsets.UTF_8));
        println("CFG written to " + outFile.getAbsolutePath());
    }

    private static class CfgOutput {
        String program_name;
        String image_base;
        List<FunctionCfg> functions;
    }

    private static class FunctionCfg {
        String name;
        String address;
        List<Block> blocks;
        List<Edge> edges;
        List<String> indirect_call_sites;
    }

    private static class Block {
        String start;
        String end;
    }

    private static class Edge {
        String from;
        String to;
        String type;
        Boolean indirect;
    }
}
