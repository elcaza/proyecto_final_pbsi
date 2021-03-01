// Main actions
document.addEventListener("DOMContentLoaded", function() {
	// Buttons
	let body = document.querySelector("body");
	let button_nav__nuevo = document.querySelector(".nav__nuevo");
	let button_nav__consultas = document.querySelector(".nav__consultas");
	let button_nav__proximosEscaneos = document.querySelector(".nav__proximosEscaneos");
	let button_scan__options__url = document.querySelector(".scan__options__url");
	let button_scan__options__file = document.querySelector(".scan__options__file");

	// Event listeners
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

	// Loading info
	set_maxdate();
	json_modulos = send_info("load_modules");
});

/**
 * Global configs
 */

// Función para enviar los datos en un json
const server_url = "https://webhook.site/c6b104c7-9414-4821-8c63-5435b75f277b";


/**
 * General Functions 
 */

function set_maxdate() {
	document.querySelector("#next_scan").min = new Date(new Date().getTime() - new Date().getTimezoneOffset() * 60000).toISOString().split("T")[0];
}

async function send_info(action) {
	switch (action) {
		case "load_modules":
			let modulos = send_json2(server_url+"/hola", {"lala":"love"});
			break;
		
		case "load_modules2":
			break;
	
		default:
			break;
	}
}

async function dummy_response(action) {
	switch (action) {
		case "load_modules":
			alert(1)
			break;
		
		case "load_modules2":
			alert(2)
			break;
	
		default:
			break;
	}
}

function send_json2(){
	fetch('https://jsonplaceholder.typicode.com/todos/1')
		.then(response => response.json())
		.then(json => load_modules(json));
}

function load_modules(json){
	console.log(json);
	let target_modulos = document.querySelector(".modulos");

	json = [
		{
			"nombre":"Modulo 1",
			"opciones":[
				{
					"opcion_nombre":"Nombre de opción",
					"descripcion":"Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
					"type":"number"
				},
				{
					"opcion_nombre":"Nombre de opción",
					"descripcion":"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
					"type":"boolean"
				}	

			]
		},
		{
			"nombre":"Modulo 2",
			"opciones":[
				{
					"opcion_nombre":"Nombre de opción",
					"descripcion":"Lorem ipsum",
					"type":"boolean"
				}				

			]
		},
		{
			"nombre":"Modulo 3",
			"opciones":[
				{
					"opcion_nombre":"Nombre de opción",
					"descripcion":"Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
					"type":"number"
				},
				{
					"opcion_nombre":"Nombre de opción",
					"descripcion":"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
					"type":"boolean"
				},
				{
					"opcion_nombre":"Nombre de opción",
					"descripcion":"Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
					"type":"number"
				}	

			]
		}
	];

	json.forEach(element => {
		console.log(element.nombre)
		let nombre = element.nombre;
		let opcion_nombre = element.opciones;

		/*
		<div class="modulos__modulo">
			<label class="modulos__switch">
				<input type="checkbox" class="modulos__checkbox">
				<span class="modulos__slider modulos__round"></span>
			</label>
			<span class="modulos__nombre">Nombre</span>
			<div class="modulos__config">
				<div class="modulos__opcion__nombre">Nombre de la opción</div>
				<div class="modulos__opcion__descripcion">
					Lorem ipsum dolor sit amet, consectetur adipiscing elit. Ut dictum lorem ut sem sagittis vulputate. Sed aliquet, neque placerat varius mollis, leo arcu fringilla magna, sit amet sollicitudin eros sapien a purus. Ut consequat mollis arcu, a feugiat nulla efficitur eget. Donec id ante sed sem egestas euismod. 
				</div>
				<div class="modulos__opcion__valor">
					Valor
				</div>
			</div>
		</div>
		*/

		// Creación de elmentos
		let modulos__modulo = document.createElement('div');
		modulos__modulo.classList.add("modulos__modulo");

		let modulos__switch = document.createElement('label');
		modulos__switch.classList.add("modulos__switch");

		let modulos__checkbox = document.createElement('input');
		modulos__checkbox.classList.add("modulos__checkbox");
		modulos__checkbox.type = "checkbox";

		let modulos__slider = document.createElement('span');
		modulos__slider.classList.add("modulos__slider");
		modulos__slider.classList.add("modulos__round");

		let modulos__nombre = document.createElement('span');
		modulos__nombre.classList.add("modulos__nombre");
		modulos__nombre.innerHTML = nombre;

		// Carga de elementos
		target_modulos.appendChild(modulos__modulo);

		modulos__modulo.appendChild(modulos__switch);
		modulos__switch.appendChild(modulos__checkbox);
		modulos__switch.appendChild(modulos__slider);
		
		modulos__modulo.appendChild(modulos__nombre);

		// Configs

		opcion_nombre.forEach(options => {
			console.log(options);
			let nombre = options.opcion_nombre;
			let descripcion = options.descripcion;
			let type = options.type;

			let modulos__config = document.createElement('div');
			modulos__config.classList.add("modulos__config");

			let modulos__opcion__nombre = document.createElement('div');
			modulos__opcion__nombre.classList.add("modulos__opcion__nombre");
			modulos__opcion__nombre.innerHTML = nombre;

			let modulos__opcion__descripcion = document.createElement('div');
			modulos__opcion__descripcion.classList.add("modulos__opcion__descripcion");
			modulos__opcion__descripcion.innerHTML = descripcion;
			
			let modulos__opcion__valor = document.createElement('div');
			modulos__opcion__valor.classList.add("modulos__opcion__valor");
			if (type === "number"){
				modulos__opcion__valor.innerHTML = "<input type='number'></input>";

			}else if (type === "boolean"){
				modulos__opcion__valor.innerHTML = '<label class="modulos__switch">\
				<input type="checkbox" class="modulos__checkbox">\
				<span class="modulos__slider modulos__round"></span>\
			</label>';
			}

			modulos__modulo.appendChild(modulos__config);
			modulos__config.appendChild(modulos__opcion__nombre);
			modulos__config.appendChild(modulos__opcion__nombre);
			modulos__config.appendChild(modulos__opcion__descripcion);
			modulos__config.appendChild(modulos__opcion__valor);
		});

		// let modulos__config = document.createElement('div');
		// modulos__config.classList.add("modulos__config");

		// let modulos__opcion__nombre = document.createElement('div');
		// modulos__opcion__nombre.classList.add("modulos__opcion__nombre");
		// modulos__opcion__nombre.innerHTML = "1111";

		// let modulos__opcion__descripcion = document.createElement('div');
		// modulos__opcion__descripcion.classList.add("modulos__opcion__descripcion");
		// modulos__opcion__descripcion.innerHTML = "2222";

		// let modulos__opcion__valor = document.createElement('div');
		// modulos__opcion__valor.classList.add("modulos__opcion__valor");
		// modulos__opcion__valor.innerHTML = "3333";

		

		// modulos__modulo.appendChild(modulos__config);
		// modulos__config.appendChild(modulos__opcion__nombre);
		// modulos__config.appendChild(modulos__opcion__nombre);
		// modulos__config.appendChild(modulos__opcion__descripcion);
		// modulos__config.appendChild(modulos__opcion__valor);

	});


	console.log(json);
}

async function send_json(url, json) {
	let response = await (async () => {
		const rawResponse = await fetch(url, {
		  method: 'POST',
		  headers: {
			'Accept': 'application/json',
			'Content-Type': 'application/json'
		  },
		  body: JSON.stringify(json)
		});
		const content = await rawResponse.json();
		return content;
	})();
	
	if(response.status.toLowerCase().includes("error")){		
		toastr.options = {
			"closeButton": false,
			"debug": false,
			"newestOnTop": false,
			"progressBar": false,
			"positionClass": "toast-top-center",
			"preventDuplicates": true,
			"showDuration": "300",
			"hideDuration": "1000",
			"timeOut": "2000",
			"extendedTimeOut": "1000",
			"showEasing": "swing",
			"hideEasing": "linear",
			"showMethod": "fadeIn",
			"hideMethod": "fadeOut"
		  }
		toastr.error(response.status,'Error');
	}else{
		toastr.options = {
			"closeButton": false,
			"debug": false,
			"newestOnTop": false,
			"progressBar": false,
			"positionClass": "toast-top-center",
			"preventDuplicates": true,
			"showDuration": "300",
			"hideDuration": "1000",
			"timeOut": "2000",
			"extendedTimeOut": "1000",
			"showEasing": "swing",
			"hideEasing": "linear",
			"showMethod": "fadeIn",
			"hideMethod": "fadeOut"
		  }
		toastr.success(response.status,'Éxito');
	}
	//return response;
	return true;
}