$(function(){
  alert('before ajax');
  // select file to encrypt
  select_file(function(data){
      alert('after success');
      data = JSON.parse(data);
      
      // handle errors
      if(data.error) {
        if(data.error_type == 'invalid')
          alert("Invalid file selected");
        document.location = '/';
        return;
      }

      // file selected
      alert('File selected: '+data.basename);
  });
});
