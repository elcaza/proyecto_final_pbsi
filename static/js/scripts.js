// Main actions
document.addEventListener("DOMContentLoaded", function() {
	// Buttons
	let body = document.querySelector("body");
	let button_nav__nuevo = document.querySelector(".nav__nuevo");
	let button_nav__consultas = document.querySelector(".nav__consultas");
	let button_nav__proximosEscaneos = document.querySelector(".nav__proximosEscaneos");
	let button_scan__options__url = document.querySelector(".scan__options__url");
	let button_scan__options__file = document.querySelector(".scan__options__file");
	let scan__start = document.querySelector(".scan__start");
	let button_exploits__options__software = document.querySelector(".exploits__options__software");
	let button_exploits__options__cms = document.querySelector(".exploits__options__cms");
	let button_add__exploits = document.querySelector(".exploits__add");
	let button_consultas__opciones__proximo = document.querySelector(".consultas__opciones__proximo");
	
	// Event listeners
	button_nav__nuevo.addEventListener("click", function(){
		body.classList.replace("vista_consultas", "vista_nuevo");
		body.classList.replace("vista_configuraciones", "vista_nuevo");
	});
	
	button_nav__consultas.addEventListener("click", function(){
		body.classList.replace("vista_nuevo", "vista_consultas");
		body.classList.replace("vista_configuraciones", "vista_consultas");
		start_consulta();
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

	button_exploits__options__software.addEventListener("click", function(){
		body.classList.replace("in_cms", "in_software");
	});

	button_exploits__options__cms.addEventListener("click", function(){
		body.classList.replace("in_software", "in_cms");
	});

	button_add__exploits.addEventListener("click", function(){
		body.classList.toggle("add__exploit");
	});

	// Loading info
	set_maxdate();
	// Función async
	json_modulos = prepara_envio("load_modules");

	/**
	 * Peticiones al backend
	 */

	// ************************************************************************************************
	// ************************************************************************************************
	// ************************************************************************************************
	// ************************************************************************************************

	// POST - ejecucion
	scan__start.addEventListener("click", function(){
		alert("iniciando scan");

		let sitio = document.querySelector(".scan__url").value;
		let file = document.querySelector(".scan__file").value;
		// let sitio = document.querySelector(".scan__url").value;
		// let sitio = document.querySelector(".scan__url").value;
		// let sitio = document.querySelector(".scan__url").value;
		/**
		 * POST - ejecucion

		Envio
		peticion = {
			"sitio":"http://localhost/joomla/",
			"fecha":"",
			"puertos" : { 
				"inicio" : 1,
				"final" : 1000
			},
			"cookie":"PHDSESSID:jnj8mr8fugu61ma86p9o96frv0",
			"profundidad":2
		}
		*/

		let peticion = {};
	});

	// ************************************************************************************************
	// ************************************************************************************************
	// ************************************************************************************************
	// ************************************************************************************************
	// POST - consulta-volcado

	function start_consulta() {
		let json_consultas = send_json_fetch(server_url+"/consulta-volcado", {});
		json_consultas = {
			"analisis_totales": 97,
			"ultima_fecha": "19/02/2021 00:07:26",
			"analisis": [
				{
					"sitios":"url",
					"fecha":"fecha"
				},
				{
					"sitios":"url",
					"fecha":"fecha"
				}
			]
		}

		document.querySelector(".consultas__analizados__numero").textContent = json_consultas.analisis_totales;
		document.querySelector(".consultas__fecha__fecha").textContent = json_consultas.ultima_fecha;
		let modulos__select = document.querySelector(".modulos__select");
		let analisis = json_consultas.analisis;

		analisis.forEach(element => {
			modulos__select.add(new Option(element.sitios, element.sitios));
		});
		
	}

	// ************************************************************************************************
	// ************************************************************************************************
	// ************************************************************************************************
	// ************************************************************************************************
	// POST - consulta-reporte

	button_consultas__opciones__proximo.addEventListener("click", function(){
		
		alert("enviando: "+ document.querySelector(".modulos__select").value);

		let peticion = {
			"sitio": document.querySelector(".modulos__select").value,
			"fecha":"NA"
		}

		send_json_fetch(server_url+"/consulta-reporte", peticion);
	});

	function aaa(){
		let json_consultas = send_json_fetch(server_url+"/consulta-volcado", {});
		
		json_consultas = {
			"analisis_totales": 97,
			"ultima_fecha": "19/02/2021 00:07:26",
			"analisis": [
				{
					"sitios":"url",
					"fecha":"fecha"
				},
				{
					"sitios":"url",
					"fecha":"fecha"
				}
			]
		}
	}

	// Envio
	// peticion = {
	// 	"sitio": "http://localhost/drupal7/",
	// 	"fecha":"01/03/2021 17:23:57"
	// }


	// ************************************************************************************************
	// ************************************************************************************************
	// ************************************************************************************************
	// ************************************************************************************************

});

/**
 * Global configs
 */

// Función para enviar los datos en un json
const server_url = "https://webhook.site/7ad7e3f3-ed67-454e-8147-c853bed2fd63";


/**
 * General Functions 
 */

function set_maxdate() {
	document.querySelector("#next_scan").min = new Date(new Date().getTime() - new Date().getTimezoneOffset() * 60000).toISOString().split("T")[0];
}

async function prepara_envio(action) {
	switch (action) {
		case "load_modules":
			let modulos = send_json_fetch(server_url+"/hola", {"lala":"love"});
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
			break;
		
		case "load_modules2":
			break;
	
		default:
			break;
	}
}

/**
 * Función que se encarga de hacer las peticiones
 */
function send_json_fetch(url, json){
	/*
	fetch(url)
		.then(response => response.json())
		.then(json => load_modules(json));

	*/	

	const data_to_send = JSON.stringify(json);
	
	let dataReceived = ""; 
	fetch(url, {
		// credentials: "same-origin",
		// mode: "same-origin",
		method: "post",
		headers: { "Content-Type": "application/json" },
		body: data_to_send
	})
		.then(resp => {
			if (resp.status === 200) {
				return resp.json()
			} else {
				console.log("Status: " + resp.status)
				return Promise.reject("server")
			}
		})
		.then(dataJson => {
			console.log("evaluando");
			try {
				dataReceived = JSON.parse(dataJson);
			} catch (error) {
				console.log(error);
			}
		})
		.catch(err => {
			console.log("fallando");
			if (err === "server") return
			console.log(err)
		})
		
		console.log(`Received: ${dataReceived}`);
		load_modules({});	
}

function load_modules(json){
	console.log(json);
	let target_modulos = document.querySelector(".modulos");

	json = [
		{
			"nombre":"Configuraciones generales",
			"opciones":[
				{
					"opcion_nombre":"Puertos a escanear",
					"descripcion":"Selecciona los --top-ports a escanear",
					"type":"number"
				},
				{
					"opcion_nombre":"Cookie",
					"descripcion":"Seleccione una cookie. (Opcional)",
					"type":"text"
				},
				{
					"opcion_nombre":"Profundidad",
					"descripcion":"Probar exploits que coincidan completamente (1-4).\
					1) a\
					2) b",
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

			}else if (type === "text"){
				modulos__opcion__valor.innerHTML = "<input type='text'></input>";

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