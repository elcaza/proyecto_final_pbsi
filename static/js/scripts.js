// Variable global
let json_consultas;
let json_proximos_escaneos;
// Main actions
document.addEventListener("DOMContentLoaded", function() {
	// Buttons
	let body = document.querySelector("body");
	let button_nav__nuevo = document.querySelector(".nav__nuevo");
	let button_nav__consultas = document.querySelector(".nav__consultas");
	let button_nav__proximosEscaneos = document.querySelector(".nav__proximosEscaneos");
	let button_nav__exploits = document.querySelector(".nav__exploits");
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
		body.classList.replace("vista_exploits", "vista_nuevo");
	});
	
	button_nav__consultas.addEventListener("click", function(){
		body.classList.replace("vista_nuevo", "vista_consultas");
		body.classList.replace("vista_configuraciones", "vista_consultas");
		body.classList.replace("vista_exploits", "vista_consultas");
		start_consulta();
	});
	
	button_nav__proximosEscaneos.addEventListener("click", function(){
		body.classList.replace("vista_nuevo", "vista_configuraciones");
		body.classList.replace("vista_consultas", "vista_configuraciones");
		body.classList.replace("vista_exploits", "vista_configuraciones");
		start_proximos_escaneos();
	});

	button_nav__exploits.addEventListener("click", function(){
		body.classList.replace("vista_nuevo", "vista_exploits");
		body.classList.replace("vista_consultas", "vista_exploits");
		body.classList.replace("vista_configuraciones", "vista_exploits");
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
		//@cromos
		alert("Añadiendo exploit");

		let opcion = "";
		let nombre = document.querySelector("#exploit_name").value;
		let contenido_exploit = document.querySelector("#contenido_exploit").value;
		let tecnologia = document.querySelector("#tecnologia").value
		let exploit_cve = document.querySelector("#exploit_cve").value;
		let exploit_software = document.querySelector("#exploit_software").value;
		let exploit_software_version = document.querySelector("#exploit_software_version").value;
		let exploit_cms = document.querySelector("#exploit_cms").value;
		let exploit_categoria = document.querySelector("#exploit_categoria").value;
		let exploit_extension = document.querySelector("#exploit_extension").value;
		let exploit_version = document.querySelector("#exploit_version").value;

		if ( document.querySelector("body").classList.contains("in_software") ){
			opcion = "software";
		} else if ( document.querySelector("body").classList.contains("in_cms") ) {
			opcion = "cms";
		}


		// exploits-crear
		let peticion = {
			"opcion":opcion, // ( software | cms )
			"nombre":nombre,
			"contenido_exploit":contenido_exploit,
			"tecnologia":tecnologia,
			"exploit_cve":exploit_cve,
			"exploit_software":exploit_software,
			"exploit_software_version":exploit_software_version,
			"exploit_cms":exploit_cms,
			"exploit_categoria":exploit_categoria,
			"exploit_extension":exploit_extension,
			"exploit_version":exploit_version
		}
		console.log(peticion);

		send_json_fetch(server_url+"/exploits-crear", peticion);
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
		//alert("iniciando scan");

		let sitio = document.querySelector(".scan__url").value;
		let file = document.querySelector(".scan__file").value;
		let fecha = document.querySelector("#next_scan").value
		let puertos = document.querySelector("#modulos_puertos").value;
		let cookie = document.querySelector("#modulos_cookie").value;
		let profundidad = document.querySelector("#profundidad").value;
		//@cromos
		let redireccionamiento = document.querySelector("#redireccionamiento").checked;
		let lista_negra = document.querySelector("#lista_negra").value;
		let array_lista_negra = [];

		// Cada nueva línea será un elemento del array
		lista_negra = lista_negra.split('\n');
		
		lista_negra.forEach(element => {
			// corroborar si el elemento es una url
			// Pendiente
			array_lista_negra.push(element);
		});

		// alert(redireccionamiento)
		// alert(lista_negra)		

		let peticion = {
			"sitio":sitio,
			"fecha":fecha,
			"puertos":{
				"inicio":1,
				"final":puertos
			},
			"cookie":cookie,
			"profundidad":profundidad,
			// @cromos
			"redireccionamiento":redireccionamiento,
			"lista_negra":array_lista_negra
		}

		send_json_fetch(server_url+"/ejecucion", peticion);
	});

	// ************************************************************************************************
	// ************************************************************************************************
	// ************************************************************************************************
	// ************************************************************************************************
	// POST - consulta-volcado
	// Variable global
	json_consultas;
	function start_consulta() {
		// @cromos
		send_json_fetch_2(server_url+"/consulta-volcado", {})
		.then(
			json_respuesta =>{
				let array_sites = [];
				document.querySelector(".consultas__analizados__numero").textContent = json_respuesta.analisis_totales;
				document.querySelector(".consultas__fecha__fecha").textContent = json_respuesta.ultima_fecha;
				
				let modulos__select = document.querySelector(".modulos__select");
				let analisis = json_respuesta.analisis;
		
				analisis.forEach(element => {
					array_sites.push(element.sitio);
				});
		
				array_sites = [...new Set(array_sites)];
		
				modulos__select.innerHTML = "";
				console.log(array_sites)
				array_sites.forEach(element => {
					modulos__select.add(new Option(element, element));
				});
				json_consultas = json_respuesta;
			}
		)
	}


	json_proximos_escaneos;
	function start_proximos_escaneos() {
		send_json_fetch_2(server_url+"/proximos-escaneos", {})
		.then(
			json_respuesta =>{
				json_proximos_escaneos = json_respuesta;
				// @capi checa esto plx
				let target_modulos = document.querySelector(".main__proximosEscaneos__contenedor");
				target_modulos.innerHTML = "";
				json_proximos_escaneos.forEach(element => {
					console.log(element)

					let sitios = element.sitio;
					let estado = element.estado;
					/*
					<div class="main__proximosEscaneos__datos">
						<div class="main__proximosEscaneos__sitio">
							<span>www.site.com</span>
						</div>
						<div class="main__proximosEscaneos__fecha">
							Fecha: <span>22/03/2021</span>
						</div>
					</div>
					*/

					// Creación de elmentos
					let consultas__sitio = document.createElement('div');
					consultas__sitio.classList.add("main__proximosEscaneos__datos");

					let consultas__sitio__url = document.createElement('div');
					consultas__sitio__url.classList.add("main__proximosEscaneos__sitio");

					let span_site = document.createElement('span');
					span_site.classList.add("main__proximosEscaneos__sitio");
					span_site.textContent = sitios;

					let consultas__sitio__estado = document.createElement('div');
					consultas__sitio__estado.classList.add("main__proximosEscaneos__fecha");

					let span_estado = document.createElement('span');
					span_estado.classList.add("main__proximosEscaneos__fecha");
					span_estado.textContent = estado;

					// Carga de elementos
					consultas__sitio.appendChild(consultas__sitio__url);
					consultas__sitio__url.appendChild(span_site);

					consultas__sitio.appendChild(consultas__sitio__estado);
					consultas__sitio__estado.appendChild(span_estado);

					// Pintar el elmento terminado
					target_modulos.appendChild(consultas__sitio);

				}); // Fin carga de botones y sitios
			})
	}

	// ************************************************************************************************
	// ************************************************************************************************
	// ************************************************************************************************
	// ************************************************************************************************
	// POST - consulta-reporte

	button_consultas__opciones__proximo.addEventListener("click", function(){
		let value_select = document.querySelector(".modulos__select").value;
		// let analisis = json_consultas.analisis;
		// analisis.forEach(element => {
		// 	if (element.sitios === value_select){

		// 	}
		// });
		
		
		// alert("enviando: "+ document.querySelector(".modulos__select").value);

		// let peticion = {
		// 	"sitio": document.querySelector(".modulos__select").value,
		// 	"fecha":"NA"
		// }

		// send_json_fetch(server_url+"/consulta-reporte", peticion);

		load_sites(value_select);
	});

	// function aaa(){
	// 	let json_consultas = send_json_fetch(server_url+"/consulta-volcado", {});
		
	// 	json_consultas = {
	// 		"analisis_totales": 97,
	// 		"ultima_fecha": "19/02/2021 00:07:26",
	// 		"analisis": [
	// 			{
	// 				"sitios":"url",
	// 				"fecha":"fecha"
	// 			},
	// 			{
	// 				"sitios":"url",
	// 				"fecha":"fecha"
	// 			}
	// 		]
	// 	}
	// }

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
const server_url = "http://localhost:3000";


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
async function send_json_fetch_2(url, json){
	const response = await fetch(url, {
		method: 'POST', // *GET, POST, PUT, DELETE, etc.
		mode: 'cors', // no-cors, *cors, same-origin
		cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
		credentials: 'same-origin', // include, *same-origin, omit
		headers: {
		  'Content-Type': 'application/json'
		  // 'Content-Type': 'application/x-www-form-urlencoded',
		},
		redirect: 'follow', // manual, *follow, error
		referrerPolicy: 'no-referrer', // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
		body: JSON.stringify(json) // body data type must match "Content-Type" header
	  });
	  return response.json(); // parses JSON response into native JavaScript objects
}


function send_json_fetch(url, json){
	/*
	fetch(url)
		.then(response => response.json())
		.then(json => load_modules(json));

	*/	

	const data_to_send = JSON.stringify(json);
	console.log(data_to_send)
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
				dataReceived = dataJson;
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
		// load_modules({});	
}

function load_modules(json){
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

function load_sites(value_select){
	let target_modulos = document.querySelector(".consultas__contenidor__sitio");

	analisis = json_consultas.analisis;
	console.log(typeof(analisis));
	console.log(analisis);

	document.querySelector(".consultas__contenidor__sitio").innerHTML = "";

	analisis.forEach(element => {
		console.log(element)
		let fecha = element.fecha;
		let sitios = element.sitio;

		if (value_select === sitios) {
				/*
			<div class="consultas__sitio">
				<div class="consultas__sitio__url">
					<span>www.site.com</span>
				</div>
				<div class="consultas__sitio__fecha">
					Fecha: <span>22/03/2021</span>
				</div>
				<div class="consultas__sitio__opciones">
					<button>Ver más</button>
					<button>Borrar</button>
				</div>
			</div>
			*/

			// Creación de elmentos
			let consultas__sitio = document.createElement('div');
			consultas__sitio.classList.add("consultas__sitio");

			let consultas__sitio__url = document.createElement('div');
			consultas__sitio__url.classList.add("consultas__sitio__url");

			let span_site = document.createElement('span');
			span_site.classList.add("span_site");
			span_site.textContent = sitios;

			let consultas__sitio__fecha = document.createElement('div');
			consultas__sitio__fecha.classList.add("consultas__sitio__fecha");

			let span_fecha = document.createElement('span');
			span_fecha.classList.add("span_fecha");
			span_fecha.textContent = fecha;

			let consultas__sitio__opciones = document.createElement('div');
			consultas__sitio__opciones.classList.add("consultas__sitio__opciones");

			let button_ver_mas = document.createElement('button');
			button_ver_mas.classList.add("button_ver_mas");
			button_ver_mas.innerText = "Ver más";

			let button_borrar = document.createElement('button');
			button_borrar.classList.add("button_borrar");
			button_borrar.innerText = "Borrar";

			// Carga de elementos
			consultas__sitio.appendChild(consultas__sitio__url);
			consultas__sitio__url.appendChild(span_site);

			consultas__sitio.appendChild(consultas__sitio__fecha);
			consultas__sitio__fecha.appendChild(span_fecha);
			
			consultas__sitio.appendChild(consultas__sitio__opciones);
			consultas__sitio__opciones.appendChild(button_ver_mas);
			consultas__sitio__opciones.appendChild(button_borrar);

			// Pintar el elmento terminado
			target_modulos.appendChild(consultas__sitio);
		}
	}); // Fin carga de botones y sitios

	let elements;
	// Agregar funciones al botón "ver más"
	elements = document.querySelectorAll(".button_ver_mas");

	let action_ver_mas = function(site, date) {
		send_json_fetch_2(server_url+"/consulta-reporte", {"sitio":site,"fecha":date})
		.then(
			json_respuesta =>{
				window.open("http://localhost:3000/reporte");
			}
		);
	};

	Array.from(elements).forEach(function(element) {
		element.addEventListener('click', function(){
			let element_parent = element.closest(".consultas__sitio");
			let url = element_parent.childNodes[0].innerText;
			let date = element_parent.childNodes[1].innerText;
			action_ver_mas(url, date);
		});
	});

	// Agregar funciones al botón "Borrar"
	elements = document.querySelectorAll(".button_borrar");

	let action_borrar = function(site, date) {
		alert("Borrar " + site + " " + date);
		console.log("Borrar " + site + " " + date);
	};

	Array.from(elements).forEach(function(element) {
		element.addEventListener('click', function(){
			let element_parent = element.closest(".consultas__sitio");
			let url = element_parent.childNodes[0].innerText;
			let date = element_parent.childNodes[1].innerText;
			action_borrar(url, date);
		});
	});


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