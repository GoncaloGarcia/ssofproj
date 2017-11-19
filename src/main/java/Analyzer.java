import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import java.util.stream.Collectors;


public class Analyzer {

    /**
     * A list of Pattern objects that is used to perform the analysis
     * For more information about patterns check {@link Pattern}
     */
    private List<Pattern> patterns;

    /**
     * A list of the names of the functions that sanitizes the data
     */
    private List<String> sanitizes;

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
     * Defaults to false, which means the program is not vulnerable
     * and only changes once, which means the program cannot become
     * vulnerable and later safe.
     */
    private boolean isProgramVulnerable;

    /**
     * Stores if the string with encapsed variables is vulnerable
     */
    private boolean encapsedVulnerable;

    /**
     *  Stores the token that is being checked in the if if it's a string.
     */
    private String ifConditionTokenString;


    /**
     * Constructor for Analyzer
     *
     * @param patternFile The file containing the patterns that are used to
     *                    evaluate the safety of the slice
     */
    public Analyzer(String patternFile) {
        patterns = new LinkedList<Pattern>();
        buildPatternsList(patternFile);
        sanitizes = new LinkedList<String>();
        isVariableVulnerable = new HashMap<>();
    }


    /**
     * Loads the pattern file into a List of Pattern objects.
     *
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
            if (line.equals("-"))
                patterns.add(new Pattern(name, entryPoints, sanitizers, sinks)); //When the delimiter is reached create the object
            else if (lineNumber % 5 == 0) name = line; //First line is always the name
            else if (lineNumber % 5 == 1)
                entryPoints = Arrays.asList(line.split(",")); //Second line is always the entry points
            else if (lineNumber % 5 == 2)
                sanitizers = Arrays.asList(line.split(",")); //Third line is always the sanitizers
            else if (lineNumber % 5 == 3) sinks = Arrays.asList(line.split(",")); //Fourth line is always the sinks
            lineNumber++;
        }
    }




    public static void main(String[] args) {

        Analyzer analyzer = new Analyzer("patterns.txt");
        analyzer.startAnalysis("slice8safe.json");

    }

    /**
     * Entry point for the Analysis
     *
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
        handleNodeKind(currentNode, kind);
        if (children.size() > index + 1) {
            analyze(index + 1);
        } else if (!isProgramVulnerable) {
            System.out.println("Program is safe");
            if (!sanitizes.isEmpty()) {
                System.out.println("Sanitizes funtions: ");
                for (String s : sanitizes) {
                    System.out.println("\t" + s);
                }
            }
        }

    }


    /**
     * Picks the correct code path for the given node based on the kind parameter
     * @param currentNode The node that contains the parameters necessary to evaluate the code path
     * @param kind The kind of operation of the line corresponding to this node
     */
    private void handleNodeKind(JsonNode currentNode, String kind) {
        if (kind.equals("assign")) {
            boolean vulnerable = handleAssign(currentNode);
            //Sets the current vulnerability status of the analyzed variable to the status of what is assigned to it
            isVariableVulnerable.put(currentNode.get("left").get("name").asText(), vulnerable);
        } else if (kind.equals("echo")) {
            handleEcho(currentNode);
        } else if (kind.equals("if")) {
            handleIf(currentNode);
        } else if (kind.equals("while")) {
            handleWhile(currentNode);
        }
    }


    /**
     * Handles a while loop.
     * Since it's not possible to run the while loop and check the variables, it's necessary to figure out
     * the number of times the content of the loop has to be iterated.
     * To do that we run the loop N times and at each iteration we verify that a previously untainted variable has been tainted
     * and that previously tainted variables remain tainted. If any of these conditions is broken, the iteration stops and the
     * variables are evaluated as such.
     * @param node The node that contains the parameters necessary to evaluate this loop
     */
    private void handleWhile(JsonNode node) {
        Map<String, Boolean> prevIteration = new HashMap<>();
        prevIteration.putAll(isVariableVulnerable);
                                            //filter out untainted variables
        Map<String, Boolean> prevTainted = isVariableVulnerable.entrySet().stream().filter(Map.Entry::getValue).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        do {
            prevIteration.putAll(isVariableVulnerable);
            prevTainted = isVariableVulnerable.entrySet().stream().filter(Map.Entry::getValue).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
            for (JsonNode children : node.get("body").get("children")) {
                if (getNodeKind(children).equals("assign")) handleAssign(children);
                else if(getNodeKind(children).equals("if")) handleIf(children);
            }
        }
        while (!isVariableVulnerable.equals(prevIteration) && prevTainted.size() < (isVariableVulnerable.entrySet().stream().filter(Map.Entry::getValue).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue))).size());
    }

    /**
     * Handles an if statement. Since the condition cannot be evalueated to figure out which code path is to be ran,
     * both code paths are checked and the result is the worst case of both paths. To do that we add to the variables
     * list any variable that is found in either code path and the vulnerability level of that variable is highest among
     * each code path.
     * @param node
     */
    private void handleIf(JsonNode node) {
        Map<String, Boolean> oldVars = new HashMap<>();
        Map<String, Boolean> bodyVars = new HashMap<>();
        Map<String, Boolean> alternateVars = new HashMap<>();

        //Specifically for slice 11 we verify if the condition checks against a string and store it in case
        //that string is used to build a query in another variable
        if(getBinType(node.get("test")).equals("==") && getNodeKind(node.get("test").get("right")).equals("string")){
            ifConditionTokenString = node.get("test").get("right").get("value").asText();
        }

        oldVars.putAll(isVariableVulnerable);
        boolean bodyResult = handleIfContent(node.get("body"));
        bodyVars.putAll(isVariableVulnerable);
        boolean alternateResult = handleIfContent(node.get("alternate"));
        alternateVars.putAll(isVariableVulnerable);

        oldVars.putAll(bodyVars);
        oldVars.putAll(alternateVars);
        for (String val : oldVars.keySet()) {
            if (bodyVars.containsKey(val) && oldVars.containsKey(val)) {
                oldVars.put(val, bodyVars.get(val) || alternateVars.get(val));
            }
        }
        isVariableVulnerable = oldVars;
        ifConditionTokenString = null;
    }


    /**
     * Handles the Content of an if statement
     * @param node The node that contains the parameters necessary to evaluate this statement
     * @return The vulnerability level of the content of this if statement
     */
    private boolean handleIfContent(JsonNode node) {
        if (node.asText().equals("null")) return false;
        String kind = getNodeKind(node);
        if(kind.equals("block")) {
            for (JsonNode children : node.get("children")) {
                if (getNodeKind(children).equals("assign")) return handleAssign(children);
            }
        } else if (kind.equals("if")) handleIf(node);
        return false;
    }

    /**
     * Handles an expression of type assign.
     * The left parameter of an assignment is always a variable so it does not need to be checked.
     * The right parameter is what will be assigned to the variable and needs to be checked.
     * This method will call will call the dedicated method for the type of expression of the right
     * parameter based on the 'kind' parameter of the JSON object.
     * It will store the variable in the isVariableVulnerable map and map it to the return value of the correct handler
     *
     * @param node The node that contains the parameters necessary to evaluate this assignment.
     * @return The vulnerability status of the right parameter of the assignment expression.
     */
    private boolean handleAssign(JsonNode node) {
        isVariableVulnerable.putIfAbsent(node.get("left").get("name").asText(), false);
        boolean value = false;

        JsonNode right = node.get("right");
        String kind = getNodeKind(right);

        if (kind.equals("offsetlookup")) {
            value = handleOffsetLookup(right);
        } else if (kind.equals("bin")) {
            value = handleBin(right);
        } else if (kind.equals("call")) {
            value = handleCall(right);
        } else if (kind.equals("variable")) {
            String rightVarName = node.get("right").get("name").asText();
            isVariableVulnerable.putIfAbsent(rightVarName, false);
            boolean rightVarValue = isVariableVulnerable.get(rightVarName);
            isVariableVulnerable.put(node.get("left").get("name").asText(), rightVarValue);
            return rightVarValue;
        } else if (kind.equals("encapsed")) {
            value = handleEncapsed(right);
        }
        isVariableVulnerable.put(node.get("left").get("name").asText(), value);
        return value;
    }

    /**
     * Handles a string with encapsed variables. Checks if there are any tainted variable in the string
     *
     * @param node The node that contains the parameters necessary to evaluate this function call
     * @return the vulnerability status of the string.
     */
    private boolean handleEncapsed(JsonNode node) {
        encapsedVulnerable = false;
        node.get("value").forEach(value -> {
            if (value.get("kind").asText().equals("variable") && isVariableVulnerable.get(value.get("name").asText()) != null && isVariableVulnerable.get(value.get("name").asText())) {
                encapsedVulnerable = true;
            }
        });
        return encapsedVulnerable;
    }

    /**
     * Handles an expression of type echo.
     *
     * @param node The node that contains the parameters necessary to evaluate this assignment.
     */
    private void handleEcho(JsonNode node) {
        for (Pattern pattern : patterns) {
            verifySafeExecution(node.get("arguments").get(0), "echo", pattern);
        }
        return;
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
        if (name.equals("substr")) return handleSubstr(node);

        for (Pattern pattern : patterns) {
            verifySanitization(node, name, pattern);
            verifySafeExecution(node, name, pattern);
        }
        return false;
    }

    /**
     * Handles a call to substr.
     * Simply adds the variable to the variables list and assigns it the correct vulnerability level
     * @param node
     * @return
     */
    private boolean handleSubstr(JsonNode node) {
        JsonNode arguments = node.get("arguments");
        JsonNode variable = arguments.get(0);
        isVariableVulnerable.putIfAbsent(variable.get("name").asText(), false);
        return isVariableVulnerable.get(variable.get("name").asText());
    }


    /**
     * Verifies if the function call is a sanitization function.
     * To do that it checks if a pattern's sanitization list contains the name of the
     * function
     *
     * @param node    The node that contains the parameters necessary to evaluate this function call
     * @param name    The name of the function
     * @param pattern The pattern to be checked
     */
    private void verifySanitization(JsonNode node, String name, Pattern pattern) {
        if (pattern.getSanitization().contains(name)) {
            node.get("arguments").forEach(argument -> {
                if (getNodeKind(argument).equals("variable")) {
                    isVariableVulnerable.put(argument.get("name").asText(), false);
                    sanitizes.add(name);
                }
            });
        }
    }

    /**
     * Verifies if the function call is targetting an unsafe sink
     * To do that it checks if a pattern's sink list contains the name of the
     * function
     *
     * @param node    The node that contains the parameters necessary to evaluate this function call
     * @param name    The name of the function
     * @param pattern The pattern to be checked
     */
    private void verifySafeExecution(JsonNode node, String name, Pattern pattern) {
        if (name.equals("echo") && pattern.getSinks().contains(name)) {
            if (node.get("kind") != null && node.get("kind").asText().equals("offsetlookup")) {
                isProgramVulnerable = true;
                System.out.println("Program is vulnerable to " + pattern.getName());
            }
        } else if (pattern.getSinks().contains(name)) {
            node.get("arguments").forEach(argument -> {
                //If it's a variable and it's unsafe then the sink is compromised
                if (getNodeKind(argument).equals("variable") && isVariableVulnerable.get(argument.get("name").asText()) != null && isVariableVulnerable.get(argument.get("name").asText())) {
                    isProgramVulnerable = true;
                    System.out.println("Program is vulnerable to " + pattern.getName());
                }
            });
        }
    }


    /**
     * Handles a binary operation.
     * Basically checks the type of the bin parameter and picks the appropriate handler
     *
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
     *
     * @param left  The left operand of the concatenation
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
     *
     * @param node The node that contains the parameters necessary to evaluate this binary operand
     * @return
     */
    private boolean handleConcatSide(JsonNode node) {
        String kind = getNodeKind(node);
        if (kind.equals("bin")) {
            return handleBin(node);
            //Strings are always safe because they don't rely on the user's input.
        } else if (kind.equals("string")) {
            if(ifConditionTokenString != null && node.get("value").asText().equals(ifConditionTokenString)) return true;
            return false;
        } else if (kind.equals("variable")) {
            return isVariableVulnerable.get(node.get("name").asText());
        } else {
            return false;
        }

    }


    /**
     * Helper method to get the type of a bin operation
     *
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
     *
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
     *
     * @param node
     * @return
     */
    private String getNodeKind(JsonNode node) {
        return node.get("kind").asText();
    }


}
