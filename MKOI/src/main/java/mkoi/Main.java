package mkoi;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;

public class Main extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception{
        Parent root = FXMLLoader.load(getClass().getResource("/login.fxml"));
        primaryStage.getIcons().add(new Image("/mkoi.jpg"));
        primaryStage.setTitle("MKOI 17Z");
        primaryStage.setMinHeight(300);
        primaryStage.setMinWidth(350);
        primaryStage.setScene(new Scene(root, 350, 300));
        primaryStage.show();
    }


    public static void main(String[] args) {
        launch(args);
    }
}
