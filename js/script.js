
var ViewModel = function (){
    var self = this;
    // This function opens items for the selected category
    this.getItems = function (clickedCategory) {

        alert("hi");
        url="/ItemCatlog/" + clickedCategory + "/";
        jQuery.ajax(url,
        {
            success: function(data){
                $(#items).html($(data).items);
            }
            error: function() {
             $('#info').html('<p>An error has occurred</p>');
            },

        });
        }
        this.getItem = function(){
            alert("hi");
        }
    
 }
 ko.applyBindings(new ViewModel());
