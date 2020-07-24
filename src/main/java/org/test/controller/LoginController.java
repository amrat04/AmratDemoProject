package org.test.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

/**
 *  Login Controller : USed for login based on Spring Security
 */
@Controller
public class LoginController {

    /**
     *
     * @param model
     * @return
     */
    @GetMapping({"/", "/welcome"})
    @PreAuthorize("hasAuthority('ADMIN')")
    public String index(Model model, CsrfToken token) {
        model.addAttribute("token","12344444");
        return "index";
    }

    /**
     *
     * @param model
     * @param error
     * @param logout
     * @return
     */
    @GetMapping("/login")
    public String login(Model model, String error, String logout) {
        if (error != null)
            model.addAttribute("error", "Your username and password is invalid.");

        if (logout != null)
            model.addAttribute("message", "You have been logged out successfully.");

        return "login";
    }

}
