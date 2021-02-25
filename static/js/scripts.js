// Main actions
document.addEventListener("DOMContentLoaded", function() {
    let body = document.querySelector("body");
    let button_nav__nuevo = document.querySelector(".nav__nuevo");
    let button_nav__consultas = document.querySelector(".nav__consultas");
    let button_nav__proximosEscaneos = document.querySelector(".nav__proximosEscaneos");
    let button_scan__options__url = document.querySelector(".scan__options__url");
    let button_scan__options__file = document.querySelector(".scan__options__file");

    button_nav__nuevo.addEventListener("click", function(){
        body.classList.replace("vista_consultas", "vista_nuevo");
        body.classList.replace("vista_configuraciones", "vista_nuevo");
    });
    
    button_nav__consultas.addEventListener("click", function(){
        body.classList.replace("vista_nuevo", "vista_consultas");
        body.classList.replace("vista_configuraciones", "vista_consultas");
    });
    
    button_nav__proximosEscaneos.addEventListener("click", function(){
        body.classList.replace("vista_nuevo", "vista_configuraciones");
        body.classList.replace("vista_consultas", "vista_configuraciones");
    });

    button_scan__options__url.addEventListener("click", function(){
        body.classList.replace("file", "url");
    });

    button_scan__options__file.addEventListener("click", function(){
        body.classList.replace("url", "file");
    });

    function set_maxdate() {
        document.querySelector("#next_scan").min = new Date(new Date().getTime() - new Date().getTimezoneOffset() * 60000).toISOString().split("T")[0];
    }
    set_maxdate();
});

