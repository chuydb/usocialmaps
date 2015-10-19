(function( $ ){
    
	$.fn.multiple_list = function() {
		
		return this.each(function() {
			
			//Element to which multiple list function is attached
			var $orig = $(this);

			// create html elements - list of email addresses as unordered list
			$list = $('<ul class="multiple_emails-ul" id="'+$(this).attr('id')+1+'_list" />'); 
                        
			if ($(this).val() != '') {
				$.each(jQuery.parseJSON($(this).val()), function( index, val ) {
					$list.append($('<li class="multiple_emails-email"><span class="email_name">' + val + '</span></li>')
					    .prepend($('<a href="#!" class="multiple_emails-close" title="Remover"><i class="mdi-action-delete red-text text-lighten-1"></i></a>')
						    .click(function(e) { $(this).parent().remove(); refresh_emails($list.attr('id')); e.preventDefault(); })
                        )
					);
				});
			}
			
			var $input = $('<input type="text" class="multiple_emails-input text-center" id="'+$(this).attr('id')+1+'" />').keyup(function(event) { // input

				$list = $('#'+$(this).attr('id')+'_list');
				
				$(this).removeClass('multiple_emails-error');
				
				//space or comma or enter		 
				
				if(event.which == 188 || event.which == 13) {
					
					var val;
					if(event.which == 188) {
						val = $(this).val().slice(0, -1);
				    }else{ 
    				    val = $(this).val();
    				}
                    
                    $list.append($('<li class="multiple_emails-email"><span class="email_name">' + val + '</span></li>')
                        .prepend($('<a href="#" class="multiple_emails-close" title="Remover"><i class="mdi-action-delete red-text text-lighten-1"></i></a>')
							.click(function(e) { $(this).parent().remove(); refresh_emails($list.attr('id')); e.preventDefault(); })
                        )
					);
					refresh_emails($list.attr('id'));
					$(this).val('');
				}
			
			});

			var $container = $('<div class="multiple_emails-container" />').click(function() { $input.focus(); } ); // container div
 
			$container.append($list).append($input).insertAfter($(this)); // insert elements into DOM

			function refresh_emails (elementID) {
				var emails = new Array();
				$('#'+elementID+' .multiple_emails-email span.email_name').each(function() { emails.push($(this).html());	});
				$orig.val(JSON.stringify(emails)).trigger('change');
			}
			
			return $(this).hide();
 
          });
		
     };
	

	 
})(jQuery);