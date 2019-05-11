// ******* CONSTRAINT VALIDATION *******
// Prevents HTML Constraint validation from occuring
var forms = document.getElementsByTagName('form');
for (var i = 0; i < forms.length; i++) {
    forms[i].addEventListener('invalid', function(e) {
        e.preventDefault();
        //Possibly implement your own here.
    }, true);
}



$(".signup-submit").attr("disabled", "true");
//  ******* SUBMIT BUTTON - ENABLE/DISABLE *******
// Disable submit button on page load
$(".signup-submit").attr("disabled", "true");
// Function that enables submit button if all conditions are met
var enableSubmit = function() {
	// Signup Button
	var signupSubmit = $(".signup-submit");
	signupSubmit.attr("disabled", "true");
	// Checkmarks or ex's for error display
	var emailCheck = $("#email-check").text();
	var passwordLengthCheck = $("#password-length-check").text();
	var uppercaseCheck = $("#uppercase-check").text();
	var lowercaseCheck = $("#lowercase-check").text();
	var numberCheck = $("#number-check").text();
	var symbolCheck = $("#symbol-check").text();
	var matchCheck = $("#match-check").text();
	// Array of each validation check for email and passwords
	var checkArray = [emailCheck, passwordLengthCheck, uppercaseCheck, lowercaseCheck, numberCheck, symbolCheck, matchCheck];
	// Checks the array and returns true if each element has a check
	var checks = function(eachCheck) {
		return eachCheck == "&#10004";
	};
	// If each member of the array passes, enable the submit button
	if (checkArray.every(checks)) {
		signupSubmit.removeAttr("disabled");
	} else {
		signupSubmit.attr("disabled", "true");
	}
};




//  ******* INPUT STYLING *******
// Useful variables for email and password elements
var email = $(".signup-email");
var username = $(".signup-username");
var password1 = $(".signup-password-1");
var password2 = $(".signup-password-2");
// **** FOCUS OUT ****
// Inputs input element, error message box, and validation message
// and styles the border accordingly
var inputStyling = function(input, errorBox, message) {
	// input and length of input variable
	var inputLen = input.val().length;
	// If the length is 0, style input
	if ((errorBox.css("display") != "none") || (inputLen==0)) {
		input.css("border", "3px solid #cc0000");
		input.css("border-style", "");
		input.attr("placeholder", message);
	// If length is not 0, style input
	} else {
		input.css("border-style", "");
		input.css("border-width", "");
		input.css("border-color", "");
		input.attr("placeholder", "");
	}
};
// Email input styling on focus out
email.focusout(function() {
	inputStyling($(this), $(".email-validation"), "* Email Address Required");
});
// Username input styling on focus out
username.focusout(function() {
	inputStyling($(this), $(".email-validation"), "* Username Required");
});
// Password 1 input styling on focus out
password1.focusout(function() {
	inputStyling($(this), $(".password-validation"), "* Valid Password Required");
});
// Password 2 input styling on focus out
password2.focusout(function() {
	inputStyling($(this), $(".password-validation"), "* Valid Password Required");
});




//  ******* ERROR MESSAGES *******


// **** HELPER FUNCTIONS **** 
// Check and ex values
var check = "&#10004";
var ex = "✖";
// Helper Functions
// General keyup validation function 
// Inputs the input itself, the error, and regex expression to validate
var inputValidation = function(input, error, checks, regex) {
	// Input value
	var value = input.val();
	// If input value passes reg expression
	if (regex.test(value)) {
		// Remove error
		error.css("display", "none");
		checks.text(check);
	// If does not pass reg expression
	} else {
		// Add error back in
		error.css("display", "block");
		checks.text(ex);
	}
};
// General function to determine if passwords match
var passwordsMatch = function() {
	// Values for each password
	var password1Val = password1.val();
	var password2Val = password2.val();
	var matchItemError = $("#match-item");
	var matchCheck = $("#match-check");
	// If passwords match, remove password match error
	if (password1Val === password2Val) {
		matchItemError.css("display", "none");
		matchCheck.text(check);
	} else {
		matchItemError.css("display", "block");
		matchCheck.text(ex);
	}
};
// General function that turns on or off the error display boxes and 
// input styling
// Inputs are the list of errors and the input border
var errorDisplay = function(list, input) {
	var count = 0;
	var length = list.length;
	for (i=0; i<length; i++) {
		if (list[i].style.display == "none") {
			count += 1;
		}
		if (count == length) {
			list.parent()[0].style.display = "none";
			
			input.css("border-style", "");
			input.css("border-width", "");
			input.css("border-color", "");
			input.attr("placeholder", "");
		} else {
			list.parent()[0].style.display = "block";		
		}
	}
};
// REGEX Expressions for Input Validation
var emailRE = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
var passwordLengthRE = /^([a-zA-Z0-9!@#$%^&*]{9,35})/;
var passwordLowercaseRE = /[a-z]/;
var passwordUppercaseRE = /[A-Z]/;
var passwordNumberRE = /[0-9]/;
var passwordSymbolRE = /[!, @, #, $, %, ^, &, *]/;


// **** KEYUP **** 
// Email Input Validation
email.keyup(function() {
	// Enable submit button if all inputs correct
	enableSubmit();
	inputValidation($(this), $("#email-item"), $("#email-check"), emailRE);
	// If no errors, turn off error display box
	errorDisplay($(".email-validation li"), email);
});
// Password 1 Input Validation
password1.keyup(function() {
	// Enable submit button if all inputs correct
	enableSubmit();
	// Validate each error
	inputValidation($(this), $("#password-length-item"), $("#password-length-check"), passwordLengthRE);
	inputValidation($(this), $("#uppercase-item"), $("#uppercase-check"), passwordUppercaseRE);
	inputValidation($(this), $("#lowercase-item"), $("#lowercase-check"), passwordLowercaseRE);
	inputValidation($(this), $("#number-item"), $("#number-check"), passwordNumberRE);
	inputValidation($(this), $("#symbol-item"), $("#symbol-check"), passwordSymbolRE);
	// Make sure passwords match
	passwordsMatch();
	// If no errors, turn off error display box
	errorDisplay($(".password-validation li"), password1);
	errorDisplay($(".password-validation li"), password2);
});
// Password 2 Input Validation
password2.keyup(function() {
	// Enable submit button if all inputs correct
	enableSubmit();
	// Make sure passwords match
	passwordsMatch();
	// If no errors, turn off error display box
	errorDisplay($(".password-validation li"), password1);
	errorDisplay($(".password-validation li"), password2);
	// Enable submit button if all inputs correct
	enableSubmit();
});