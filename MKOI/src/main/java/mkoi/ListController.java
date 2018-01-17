package mkoi;

import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.IOException;

public class ListController {

    private String username;
    private String password;
    private Stage stage;

    @FXML private Button upload_button;
    @FXML private Button refresh_button;
    @FXML private Button sign_out_button;
    @FXML private Button download_button;
    @FXML private Button delete_button;
    @FXML private Button hash_button;
    @FXML private ListView<String> list_view;

    private void showServerErrorAlert(PythonResult res) {
        System.out.println(res.getStderr());
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("SERVER ERROR");
        alert.setHeaderText("Server connection error!");
        alert.setContentText("Cannot connect to server!");
        alert.showAndWait();
    }

    @FXML public void initialize() {
        PythonResult res = PythonRunner.run("ListFiles");
        if(res.isOK()) {
            System.out.println(res.getStdout());
            JSONArray files = new JSONArray(res.getStdout());
            for(int i = 0; i < files.length(); ++i) {
                String file = files.getJSONObject(i).getString("name");
                list_view.getItems().add(file);
            }
        }
        else {
            showServerErrorAlert(res);
        }
    }


    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Stage getStage() {
        return stage;
    }

    public void setStage(Stage stage) {
        this.stage = stage;
    }

    @FXML private void upload_handler () {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open file to upload...");
        File file = fileChooser.showOpenDialog(stage);
        System.out.println("Uploading " + file.getAbsolutePath());

        PythonResult res = PythonRunner.run("Download", file.getAbsolutePath());
        if(res.isOK()) {
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("File upload");
            alert.setHeaderText("File uploaded:");
            alert.showAndWait();
            refresh_handler();
        }
        else {
            showServerErrorAlert(res);
        }
    }

    @FXML private void refresh_handler() {
        list_view.getItems().clear();
        initialize();
    }

    @FXML private void sign_out_handler() throws IOException {

        username = null;
        password = null;

        Stage stage;
        Parent root;
        stage=(Stage) sign_out_button.getScene().getWindow();
        root = FXMLLoader.load(getClass().getResource("/login.fxml"));
        //create a new scene with root and set the stage
        Scene scene = new Scene(root);
        stage.setScene(scene);
        stage.show();

    }

    @FXML private void download_handler() {
        System.out.println("Downloading " + list_view.getSelectionModel().getSelectedItem());

        PythonResult res = PythonRunner.run("Download", list_view.getSelectionModel().getSelectedItem());
        if(res.isOK()) {
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("File download");
            alert.setHeaderText("File downloaded:");
            alert.showAndWait();
        }
        else {
            showServerErrorAlert(res);
        }
    }

    @FXML private void delete_handler() {
        System.out.println("Deleting " + list_view.getSelectionModel().getSelectedItem());

        PythonResult res = PythonRunner.run("Delete", list_view.getSelectionModel().getSelectedItem());
        if(res.isOK()) {
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("File delete");
            alert.setHeaderText("File deleted:");
            alert.showAndWait();
            refresh_handler();
        }
        else {
            showServerErrorAlert(res);
        }
    }

    @FXML private void hash_handler() {
        System.out.println("Downloading hash of " + list_view.getSelectionModel().getSelectedItem());

        PythonResult res = PythonRunner.run("Hash", list_view.getSelectionModel().getSelectedItem());
        if(res.isOK()) {
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("File hash");
            alert.setHeaderText("File hash:");
            alert.setContentText(res.getStdout());
            alert.showAndWait();
        }
        else {
            showServerErrorAlert(res);
        }
    }


}
