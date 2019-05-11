// Function that toggles properties for signup and login buttons
var toggleProperty = function(DOMElement1, DOMElement2, property, value1, value2) {
	if (DOMElement1.css(property) == value1) {
		DOMElement1.css(property, value2);
		DOMElement2.css(property, value1);
	} else {
		DOMElement1.css(property, value1);
	}
};


// Useful variables
// Signup and Login buttons
var signupToggle = $(".signup-toggle");
var loginToggle = $(".login-toggle");
// Signup and Login containers
var signupContainer = $(".signup-container");
var loginContainer = $(".login-container");


// When click signup, toggles bold text and form display
signupToggle.click(function() {
	// Toggles bold text for signup and login buttons
	toggleProperty(signupToggle, loginToggle, "font-weight", "400", "bold");
	// Toggles on/off display for signup and login buttons
	toggleProperty(signupContainer, loginContainer, "display", "none", "block");
});
// When click login, toggles bold text and form display
loginToggle.click(function() {
	// Toggles bold text for signup and login buttons
	toggleProperty(loginToggle, signupToggle, "font-weight", "400", "bold");
	// Toggles on/off display for signup and login buttons
	toggleProperty(loginContainer, signupContainer, "display", "none", "block");
});