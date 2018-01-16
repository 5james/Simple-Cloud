package mkoi;

import java.io.IOException;
import java.io.InputStream;

public class PythonRunner {
    static String username;
    static String password;

    public static PythonResult run(String script_name, String file_name) {
        ProcessBuilder python_script_pb = new ProcessBuilder(
                "py/Python36/python",
                "py/" + script_name + ".py",
                username,
                password,
                file_name
        );
        try {
            Process python_script = python_script_pb.start();
            InputStream out = python_script.getInputStream();
            InputStream err = python_script.getErrorStream();
            String outS = "";
            String errS = "";
            int in;
            while ((in = out.read()) != -1) {
                outS += ((char)in);
            }
            while ((in = err.read()) != -1) {
                errS += ((char)in);
            }
            return new PythonResult(outS, errS, python_script.exitValue());
        }
        catch(IOException e) {
            e.printStackTrace();
        }
        return new PythonResult("", "", -1000);
    }

    public static PythonResult run(String script_name) {
        return run(script_name, "");
    }

}
