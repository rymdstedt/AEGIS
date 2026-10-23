import javax.servlet.http.HttpServletRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

class Controller {
    private static final Logger logger = LogManager.getLogger(Controller.class);

    void handle(HttpServletRequest request) {
        String name = request.getParameter("name");
        logger.error(name);
    }
}
