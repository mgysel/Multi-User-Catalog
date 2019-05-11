// Useful Variables
var newCategoryName = $('.category-name');
//  ******* SUBMIT BUTTON - ENABLE/DISABLE *******
// Disable Submit Button
var newCategorySubmit = $(".category-submit");
newCategorySubmit.attr("disabled", "true");
// Function that enables submit button if all conditions are met
var enableSubmit = function() {
	// If length of name not 0, enable submit button
	if (newCategoryName.val().length > 0) {
		newCategorySubmit.removeAttr("disabled");
	} else {
		newCategorySubmit.attr("disabled", "true");
	}
};




// *** KEYUP Validation ***
newCategoryName.keyup(function() {
	// Enable submit button if all inputs correct
	enableSubmit();
});




// *** FOCUSOUT Validation ***
// Inputs input element, error message box, and validation message
// and styles the border accordingly
var inputStyling = function(input, message) {
	// If the length is 0, style input
	if (input.val().length == 0) {
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
// Name input styling on focus out
newCategoryName.focusout(function() {
	inputStyling($(this), "* Category Name Required");
});