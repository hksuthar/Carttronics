$(function() {
  $("#fullPage").click(function() {
    $("#rightWrapper").toggleClass("full-page");
    $("#header").toggleClass("full-page");
  });
})

$(function() {
  $("#listView li").click(function () {
    if ( $("#listView li").hasClass("list-item-active") ) {
      $("#listView li").removeClass("list-item-active");
    }
    $(this).addClass("list-item-active");
  });
});