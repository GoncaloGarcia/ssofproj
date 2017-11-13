import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.util.*;


public class Analyzer {

    /**
     * A list of Pattern objects that is used to perform the analysis
     * For more information about patterns check {@link Pattern}
     */
    private List<Pattern> patterns;

    /**
     * The root node of the AST
     */
    private JsonNode root;

    /**
     * Maps each variable found in the program to a boolean value
     * that indicates whether it is vulnerable or not at that point
     * of the analysis.
     */
    private Map<String, Boolean> isVariableVulnerable;

    /**
     * Stores whether the program is vulnerable.
     *  Defaults to false, which means the program is not vulnerable
     *  and only changes once, which means the program cannot become
     *  vulnerable and later safe.
     */
    private boolean isProgramVulnerable;


    /**
     * Constructor for Analyzer
     * @param patternFile The file containing the patterns that are used to
     *                    evaluate the safety of the slice
     */
    public Analyzer(String patternFile) {
        patterns = new LinkedList<Pattern>();
        buildPatternsList(patternFile);
        isVariableVulnerable = new HashMap<>();
    }


    /**
     * Loads the pattern file into a List of Pattern objects.
     * @param patternFile The file containing the patterns that are used to
     *                    evaluate the safety of the slice
     */
    private void buildPatternsList(String patternFile) {
        InputStream reader = Analyzer.class.getResourceAsStream(patternFile);
        Scanner scanner = new Scanner(reader);

        String name = null;
        List<String> entryPoints = new ArrayList<String>();
        List<String> sanitizers = new ArrayList<String>();
        List<String> sinks = new ArrayList<String>();
        int lineNumber = 0;

        while (scanner.hasNext()) {
            String line = scanner.nextLine();
            if (line.equals("-")) patterns.add(new Pattern(name, entryPoints, sanitizers, sinks)); //When the delimiter is reached create the object
            else if (lineNumber % 5 == 0) name = line; //First line is always the name
            else if (lineNumber % 5 == 1) entryPoints = Arrays.asList(line.split(",")); //Second line is always the entry points
            else if (lineNumber % 5 == 2) sanitizers = Arrays.asList(line.split(",")); //Third line is always the sanitizers
            else if (lineNumber % 5 == 3) sinks = Arrays.asList(line.split(",")); //Fourth line is always the sinks
            lineNumber++;
        }
    }


    public static void main(String[] args) {

        Analyzer analyzer = new Analyzer("patterns.txt");
        analyzer.startAnalysis("safeslice.json");


    }

    /**
     * Entry point for the Analysis
     * @param filename The name of the file containing the slice that is to be analyzed
     * @return True if the program is vulnerable and false if it is safe
     */
    public boolean startAnalysis(String filename) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            root = mapper.readTree(Analyzer.class.getResourceAsStream(filename));
            analyze(0);
            return isProgramVulnerable;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }


    /**
     * The main method of the analysis.
     * The root node will always have N children corresponding to N lines of code.
     * This method is called for every line of code which means that it is at the highest level
     * of abstraction and will call the dedicated method based on the kind' parameter of the JSON object.
     *
     * @param index The current line of code that is being analyzed (Starting with 0)
     */
    private void analyze(int index) {
        JsonNode children = root.path("children");
        JsonNode currentNode = children.get(index);

        String kind = getNodeKind(currentNode);
        if (kind.equals("assign")) {
            boolean vulnerable = handleAssign(currentNode);
            //Sets the current vulnerability status of the analyzed variable to the status of what is assigned to it
            isVariableVulnerable.put(currentNode.get("left").get("name").asText(), vulnerable);
        }
        if (children.size() > index + 1) {
            analyze(index + 1);
        } else if (!isProgramVulnerable) {
            System.out.println("Program is safe");
        }

    }

    /**
     * Handles an expression of type assign.
     * The left parameter of an assignment is always a variable so it does not need to be checked.
     * The right parameter is what will be assigned to the variable and needs to be checked.
     * This method will call will call the dedicated method for the type of expression of the right
     * parameter based on the 'kind' parameter of the JSON object.
     *
     * @param node The node that contains the parameters necessary to evaluate this assignment.
     * @return The vulnerability status of the right parameter of the assignment expression.
     */
    private boolean handleAssign(JsonNode node) {
        JsonNode right = node.get("right");
        String kind = getNodeKind(right);
        //System.out.println(kind);
        if (kind.equals("offsetlookup")) {
            return handleOffsetLookup(right);
        } else if (kind.equals("bin")) {
            return handleBin(right);
        } else if (kind.equals("call")) {
            return handleCall(right);
        }
        return false;
    }

    /**
     * Handles a call to a function.
     * Most calls should be used for sanitization or to target a sink
     * There is no parameter that specifies what kind of function it is,
     * so it's necessary to test if the name is contained in
     * every pattern's sinks or sanitation functions.
     *
     * @param node The node that contains the parameters necessary to evaluate this function call
     * @return Will always return false for two reasons: if the call is a sanitization function, the
     * result would be false regardless. If the call is to a sink and the sink is vulnerable then it
     * doesn't matter what the return value is as the program will terminate.
     */
    private boolean handleCall(JsonNode node) {
        JsonNode what = node.get("what");
        String name = what.get("name").asText();
        for (Pattern pattern : patterns) {
            verifySanitization(node, name, pattern);
            verifySafeExecution(node, name, pattern);
        }
        return false;
    }


    /**
     * Verifies if the function call is a sanitization function.
     * To do that it checks if a pattern's sanitization list contains the name of the
     * function
     * @param node The node that contains the parameters necessary to evaluate this function call
     * @param name The name of the function
     * @param pattern The pattern to be checked
     */
    private void verifySanitization(JsonNode node, String name, Pattern pattern) {
        if (pattern.getSanitization().contains(name)) {
            node.get("arguments").forEach(argument -> {
                if (getNodeKind(argument).equals("variable")) {
                    isVariableVulnerable.put(argument.get("name").asText(), false);
                }
            });
        }
    }

    /**
     * Verifies if the function call is targetting an unsafe sink
     * To do that it checks if a pattern's sink list contains the name of the
     * function
     * @param node The node that contains the parameters necessary to evaluate this function call
     * @param name The name of the function
     * @param pattern The pattern to be checked
     */
    private void verifySafeExecution(JsonNode node, String name, Pattern pattern) {
        if (pattern.getSinks().contains(name)) {
            node.get("arguments").forEach(argument -> {
                //If it's a variable and it's unsafe then the sink is compromised
                if (getNodeKind(argument).equals("variable") && isVariableVulnerable.get(argument.get("name").asText())) {
                    isProgramVulnerable = true;
                    System.out.println("Program is vulnerable to " + pattern.getName());
                }
            });
        }
    }


    /**
     * Handles a binary operation.
     * Basically checks the type of the bin parameter and picks the appropriate handler
     * @param node The node that contains the parameters necessary to evaluate this binary operation
     * @return The vulnerability status of the result of the binary operation.
     */
    private boolean handleBin(JsonNode node) {
        String type = getBinType(node);
        if (type.equals(".")) {
            return handleConcat(node.get("left"), node.get("right"));
        }
        return false;
    }

    /**
     * Outer method to deal with concatenatenation.
     * Analyzes each side separately and if either is unsafe then the result
     * of the concatenation is unsafe
     * @param left The left operand of the concatenation
     * @param right The right operand of the concatenation
     * @return The vulnerability status of the result of the concatenation
     */
    private boolean handleConcat(JsonNode left, JsonNode right) {
        return handleConcatSide(left) || handleConcatSide(right);
    }

    /**
     * Handles each side of a concatenation operation.
     * Calculates the appropriate vulnarability status based on the kind parameter
     * of the node
     * @param node The node that contains the parameters necessary to evaluate this binary operand
     * @return
     */
    private boolean handleConcatSide(JsonNode node) {
        String kind = getNodeKind(node);
        if (kind.equals("bin")) {
            return handleBin(node);
            //Strings are always safe because they don't rely on the user's input.
        } else if (kind.equals("string")) {
            return false;
        } else if (kind.equals("variable")) {
            return isVariableVulnerable.get(node.get("name").asText());
        } else {
            return false;
        }

    }


    /**
     * Helper method to get the type of a bin operation
     * @param node
     * @return
     */
    private String getBinType(JsonNode node) {
        return node.get("type").asText();
    }


    /**
     * Offset lookup is something like $_GET['abc']
     * To see if it is vulnerable all that's necessary is to verify is the name
     * of the method is contained in the EntryPoints of any pattern.
     * @param node The node that contains the parameters necessary to evaluate this lookup
     * @return
     */
    private boolean handleOffsetLookup(JsonNode node) {
        JsonNode what = node.get("what");
        //The pattern file doesn't prepend $ but the AST does
        String name = "$" + what.get("name").asText();
        List<Pattern> acceptedPatterns = new ArrayList<>();
        boolean vulnerable = false;
        for (Pattern pattern : patterns) {
            if (pattern.getEntryPoints().contains(name)) {
                acceptedPatterns.add(pattern);
                vulnerable = true;
            }
        }
        //Remove the unnecessary patterns as they won't be applicable in future calculations
        patterns = acceptedPatterns;
        return vulnerable;
    }


    /**
     * Helper method to get the kind parameter of the nodes
     * @param node
     * @return
     */
    private String getNodeKind(JsonNode node) {
        return node.get("kind").asText();
    }


}
