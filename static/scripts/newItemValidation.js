// Useful Variables
var newItemName = $('.item-name');
var newItemDescription = $('.item-description');
//  ******* SUBMIT BUTTON - ENABLE/DISABLE *******
// Disable Submit Button
var newItemSubmit = $(".item-submit");
newItemSubmit.attr("disabled", "true");
// Function that enables submit button if all conditions are met
var enableSubmit = function() {
	// If length of name and description not 0, enable submit button
	if ((newItemName.val().length > 0) && (newItemDescription.val().length > 0)) {
		newItemSubmit.removeAttr("disabled");
	} else {
		newItemSubmit.attr("disabled", "true");
	}
};




// *** KEYUP Validation ***
newItemName.keyup(function() {
	// Enable submit button if all inputs correct
	enableSubmit();
});
newItemDescription.keyup(function() {
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
// Item Name input styling on focus out
newItemName.focusout(function() {
	inputStyling($(this), "* Item Name Required");
});
// Item Description input styling on focus out
newItemDescription.focusout(function() {
	inputStyling($(this), "* Item Description Required");
});