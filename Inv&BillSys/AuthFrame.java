import javax.swing.*;
import java.awt.*;
import java.sql.SQLException;

public class AuthFrame extends JFrame {

    private static final String LOGIN = "login";
    private static final String REGISTER = "register";
    private static final int WIDTH = 460;

    private final CardLayout cards = new CardLayout();
    private final JPanel deck = new JPanel(cards);
    private final LoginPage loginPage;
    private final RegisterPage registerPage;

    public AuthFrame() {
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setResizable(false);

        loginPage = new LoginPage(this::openInventory, this::showRegister);
        registerPage = new RegisterPage(this::accountCreated, this::showLogin);
        deck.add(loginPage, LOGIN);
        deck.add(registerPage, REGISTER);
        setContentPane(deck);

        showLogin();
        setVisible(true);

        try {
            Auth.ensureUsersTable();
        } catch (SQLException ex) {
            loginPage.showError(Auth.explain(ex));
        }
    }

    private void showLogin() {
        showPage(LOGIN, "Login", 520, loginPage.getDefaultButton());
        loginPage.focusFirstField();
    }

    private void showRegister() {
        showPage(REGISTER, "Register", 660, registerPage.getDefaultButton());
        registerPage.focusFirstField();
    }

    private void showPage(String name, String title, int height, JButton enterButton) {
        cards.show(deck, name);
        deck.setPreferredSize(new Dimension(WIDTH, height));
        setTitle("ICF Inventory & Billing System - " + title);
        getRootPane().setDefaultButton(enterButton);
        pack();
        setLocationRelativeTo(null);
    }

    private void accountCreated(String username) {
        showLogin();
        loginPage.prefill(username);
        loginPage.showSuccess("Account created! Please log in.");
    }

    private void openInventory() {
        new Main();
        dispose();
    }
}