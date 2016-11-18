package org.launchcode.blogz.controllers;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.launchcode.blogz.models.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class AuthenticationController extends AbstractController {
	
	@RequestMapping(value = "/signup", method = RequestMethod.GET)
	public String signupForm() {
		return "signup";
	}
	
	@RequestMapping(value = "/signup", method = RequestMethod.POST)
	public String signup(HttpServletRequest request, Model model) {
		
		// TODO - implement signup
		
		//get parameters from request
		String pass = request.getParameter("password");
		String username = request.getParameter("username");
		String verify = request.getParameter("verify");
		//validate parameters
		if(!User.isValidUsername(username))
		{
			model.addAttribute("username_error", "Invalid Username, please try again");
			return "signup";
		}
		if(!User.isValidPassword(pass))
		{
			model.addAttribute("password_error", "Invalid Password, please try again");
			return "signup";
		}
		if(!pass.equals(verify))
		{
			model.addAttribute("verify_error", "Passwords do not match, please try again");
			return "signup";
		}
		//create new user
		User user = new User(username,pass);
		HttpSession session = request.getSession(); //get session
		setUserInSession(session, user); //Sets user with session
		userDao.save(user);
		return "redirect:blog/newpost";
	}
	
	@RequestMapping(value = "/login", method = RequestMethod.GET)
	public String loginForm() {
		return "login";
	}
	
	@RequestMapping(value = "/login", method = RequestMethod.POST)
	public String login(HttpServletRequest request, Model model) {
		
		// TODO - implement login
		String pass = request.getParameter("password");
		String username = request.getParameter("username");
		User user = userDao.findByUsername(username);
		//check against empty username
		if (username == "" || username == null) 
		{
			model.addAttribute("error","Please enter a username");
			return "login";
		}
		//check against empty password
		else if (pass == "" || pass ==null)
		{
			model.addAttribute("error", "Please enter a password");
			return "login";
		}
		//check to see if there is a user in database with same name
		else if (user == null)
		{
			model.addAttribute("error","Please enter a valid username");
			return "login";
		}
		//check password
		else if (user.isMatchingPassword(pass))
		{
			model.addAttribute("error", "Please enter the correct password");
		}
		setUserInSession(request.getSession(), user);	
		
		return "redirect:blog/newpost";
	}
	
	@RequestMapping(value = "/logout", method = RequestMethod.GET)
	public String logout(HttpServletRequest request){
        request.getSession().invalidate();
		return "redirect:/";
	}
}
