package mkoi;

import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.stage.Stage;
import java.io.IOException;

public class LoginController {

    @FXML private TextField ip_field;
    @FXML private TextField port_field;
    @FXML private PasswordField password_field;
    @FXML private TextField username_field;
    @FXML private Button sign_button;

    public LoginController() {

    }

    @FXML
    private void sign_in_handler() throws IOException {
        PythonRunner.username = username_field.getText();
        PythonRunner.password = password_field.getText();
        PythonResult res = PythonRunner.run("CheckCredentials");
        if(res.isOK()) {
            Stage stage;
            FXMLLoader root;
            stage=(Stage) sign_button.getScene().getWindow();
            root = new FXMLLoader(getClass().getResource("/list.fxml"));
            Parent parent = root.load();
            ListController controller = root.<ListController>getController();
            controller.setUsername(username_field.getText());
            controller.setPassword(password_field.getText());
            //create a new scene with root and set the stage
            Scene scene = new Scene(parent);
            stage.setScene(scene);
            controller.setStage(stage);
            stage.show();
        }
        else {
            System.out.println(res.getStderr());
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("ERROR");
            alert.setHeaderText("Credentials error!");
            alert.setContentText("Invalid username or password!");
            alert.showAndWait();
        }
    }

}
