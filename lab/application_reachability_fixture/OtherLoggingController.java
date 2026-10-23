import javax.servlet.http.HttpServletRequest;
import com.example.other.LogManager;
import com.example.other.Logger;

class OtherLoggingController {
    private static final Logger logger = LogManager.getLogger(OtherLoggingController.class);

    void handle(HttpServletRequest request) {
        String name = request.getParameter("name");
        logger.error(name);
    }
}
