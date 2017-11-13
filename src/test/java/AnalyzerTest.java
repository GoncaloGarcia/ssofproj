import org.junit.Test;
import static org.junit.Assert.*;

public class AnalyzerTest {

    /**
     * echo 'Hello World';
     */
    @Test
    public void testEchoSlice(){
        Analyzer analyzer = new Analyzer("patterns.txt");
        boolean unsafe = analyzer.startAnalysis("slice.json");
        assertFalse(unsafe);
    }

    /**
     * $u = $_GET['username'];
     * $q = "SELECT pass FROM users WHERE user='".$u."'";
     * $query = mysql_query($q);
     */
    @Test
    public void testHardSlice(){
        Analyzer analyzer = new Analyzer("patterns.txt");
        boolean unsafe = analyzer.startAnalysis("hardslice.json");
        assertTrue(unsafe);
    }

    /**
     * $u = $_GET['username'];
     * $q = "SELECT pass FROM users WHERE user='".mysql_real_escape_string($u)."'";
     * $query = mysql_query($q);
     */
    @Test
    public void testSafeSlice(){
        Analyzer analyzer = new Analyzer("patterns.txt");
        boolean unsafe = analyzer.startAnalysis("safeslice.json");
        assertFalse(unsafe);
    }




}
