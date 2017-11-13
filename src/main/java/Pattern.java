import java.util.List;


/**
 * All patterns have 4 elements:
    • name of vulnerability (e.g., SQL injection)
    • a set of entry points (e.g., $_GET, $_POST),
    • a set of sanitization/validation functions (e.g., mysql_real_escape_string),
    • and a set of sensitive sinks (e.g., mysql_query).

 * If the data flow passes through a sanitization/validation function, there is no vulnerability;
 * if it does not pass through a sanitization/validation function, there is a vulnerability.
 *
 */
public class Pattern {

    private String name;
    private List<String> entryPoints;
    private List<String> sanitization;
    private List<String> sinks;

    public Pattern(String name, List<String> entryPoints, List<String> sanitization, List<String> sinks) {
        this.name = name;
        this.entryPoints = entryPoints;
        this.sanitization = sanitization;
        this.sinks = sinks;
    }

    public String getName() {
        return name;
    }

    public List<String> getEntryPoints() {
        return entryPoints;
    }

    public List<String> getSanitization() {
        return sanitization;
    }

    public List<String> getSinks() {
        return sinks;
    }


}
