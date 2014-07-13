function select_file(callback) {
  $.ajax({
    url: '/select_file',
    success: callback
  });
}
