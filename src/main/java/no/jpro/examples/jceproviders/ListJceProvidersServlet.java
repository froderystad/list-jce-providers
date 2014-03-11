package no.jpro.examples.jceproviders;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.Provider;
import java.security.Security;

@WebServlet(urlPatterns = "/ListJceProviders")
public class ListJceProvidersServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        PrintWriter writer = response.getWriter();

        for (Provider provider : Security.getProviders()) {
            writer.println(provider.toString());
        }
    }
}
