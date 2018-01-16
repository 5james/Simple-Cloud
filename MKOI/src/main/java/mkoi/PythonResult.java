package mkoi;

public class PythonResult {
    private String stdout;
    private String stderr;
    private int code;

    public PythonResult(String stdout, String stderr, int code) {
        this.stdout = stdout;
        this.stderr = stderr;
        this.code = code;
    }

    public String getStdout() {
        return stdout;
    }

    public void setStdout(String stdout) {
        this.stdout = stdout;
    }

    public String getStderr() {
        return stderr;
    }

    public void setStderr(String stderr) {
        this.stderr = stderr;
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public Boolean isOK() {
        return code == 0;
    }

    public Boolean isErr() {
        return code != 0;
    }
}
