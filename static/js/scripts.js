
// Variable global
let json_consultas;
let json_proximos_escaneos;
let json_consultas_exploits;

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
	let button_exploits__editar = document.querySelector(".exploits__editar");
	let button_exploits__borrar = document.querySelector(".exploits__borrar");
	
	// ************************************************************************************************
	// ************************************************************************************************
	// ************************************************************************************************
	// ************************************************************************************************
	// POST - exploits-individual

	/**
	 * Función que realiza una peticion a la app para obtener los datos completos del exploit
	 */ 
	button_exploits__editar.addEventListener("click", function(){
		
		let value_select = document.querySelector(".exploits__select").value;

		peticion = { "exploit":value_select }
		send_json_fetch(server_url+"/exploits-editar", peticion)
		.then(json_respuesta =>{
			
			if (json_respuesta.software === undefined){
				response = {
					"exploit":json_respuesta.exploit,
					"extension":json_respuesta.extension,
					"cve":json_respuesta.cve,
					"cms":{
						"cms_nombre":json_respuesta.cms.cms_nombre,
						"cms_categoria":json_respuesta.cms.cms_categoria,
						"cms_extension_nombre":json_respuesta.cms.cms_extension_nombre,
						"cms_extension_version":json_respuesta.cms.cms_extension_version
					}
				}
			} else { 
				response = {
					"exploit":json_respuesta.exploit,
					"extension":json_respuesta.extension,
					"cve":json_respuesta.cve,
					"software":{
						"software_nombre":json_respuesta.software.software_nombre,
						"software_version":json_respuesta.software.software_version
					}
				}
			}

	
			let explot_name = document.querySelector("#exploit_name");
			let contenido_exploit_valor = document.getElementById("contenido_exploit_valor");
			let tecnologia = document.querySelector("#tecnologia");
			let exploit_cve = document.querySelector("#exploit_cve");
	
			explot_name.value = response.exploit;
			contenido_exploit_valor.innerHTML = json_respuesta.exploit
			tecnologia.value = response.extension;
			exploit_cve.value = response.cve;
	
			// software
			if ('software' in response) {
				document.querySelector("body").classList.replace("in_cms", "in_software");
				let exploit_software = document.querySelector("#exploit_software");
				let exploit_software_version = document.querySelector("#exploit_software_version");
	
				exploit_software.value = response.software.software_nombre;
				exploit_software_version.value = response.software.software_version;
				
			} //cms
			else if('cms' in response) {
				document.querySelector("body").classList.replace("in_software", "in_cms");
				let exploit_cms = document.querySelector("#exploit_cms");
				let exploit_categoria = document.querySelector("#exploit_categoria");
				let exploit_extension = document.querySelector("#exploit_extension");
				let exploit_version = document.querySelector("#exploit_version");
	
				exploit_cms.value = response.cms.cms_nombre;
				exploit_categoria.value = response.cms.cms_categoria;
				exploit_extension.value = response.cms.cms_extension_nombre;
				exploit_version.value = response.cms.cms_extension_version;
			}
		});
	});

	/**
	 * Función que carga la vista de nuevo analisis
	 */ 
	button_nav__nuevo.addEventListener("click", function(){
		body.classList.replace("vista_consultas", "vista_nuevo");
		body.classList.replace("vista_configuraciones", "vista_nuevo");
		body.classList.replace("vista_exploits", "vista_nuevo");
	});
	
	/**
	 * Función que carga la vista de consultas de reportes
	 */ 
	button_nav__consultas.addEventListener("click", function(){
		body.classList.replace("vista_nuevo", "vista_consultas");
		body.classList.replace("vista_configuraciones", "vista_consultas");
		body.classList.replace("vista_exploits", "vista_consultas");
		start_consulta();
	});
	
	/**
	 * Función que carga la vista de proximos escaneos
	 */ 
	button_nav__proximosEscaneos.addEventListener("click", function(){
		body.classList.replace("vista_nuevo", "vista_configuraciones");
		body.classList.replace("vista_consultas", "vista_configuraciones");
		body.classList.replace("vista_exploits", "vista_configuraciones");
		start_proximos_escaneos();
	});

	/**
	 * Función que carga la vista de exploits
	 */ 
	button_nav__exploits.addEventListener("click", function(){
		body.classList.replace("vista_nuevo", "vista_exploits");
		body.classList.replace("vista_consultas", "vista_exploits");
		body.classList.replace("vista_configuraciones", "vista_exploits");

		start_consulta_exploits();
	});

	/**
	 * Función que habilita la url
	 */ 
	button_scan__options__url.addEventListener("click", function(){
		body.classList.replace("file", "url");
	});

	/**
	 * Función que habilita el archivo
	 */ 
	button_scan__options__file.addEventListener("click", function(){
		body.classList.replace("url", "file");
	});

	/**
	 * Función que habilita las opciones de software
	 */ 
	button_exploits__options__software.addEventListener("click", function(){
		body.classList.replace("in_cms", "in_software");
		let exploit_software = document.querySelector("#exploit_software");
		let exploit_software_version = document.querySelector("#exploit_software_version");
		let exploit_cms = document.querySelector("#exploit_cms");
		let exploit_categoria = document.querySelector("#exploit_categoria");
		let exploit_extension = document.querySelector("#exploit_extension");
		let exploit_version = document.querySelector("#exploit_version");

		exploit_software.value = ""
		exploit_software_version.value = ""
		exploit_cms.value = ""
		exploit_categoria.value = ""
		exploit_extension.value = ""
		exploit_version.value = ""
	});

	/** 
	 * Función que habilita las funciones de cms
	 */
	button_exploits__options__cms.addEventListener("click", function(){
		body.classList.replace("in_software", "in_cms");
		let exploit_software = document.querySelector("#exploit_software");
		let exploit_software_version = document.querySelector("#exploit_software_version");
		let exploit_cms = document.querySelector("#exploit_cms");
		let exploit_categoria = document.querySelector("#exploit_categoria");
		let exploit_extension = document.querySelector("#exploit_extension");
		let exploit_version = document.querySelector("#exploit_version");

		exploit_software.value = ""
		exploit_software_version.value = ""
		exploit_cms.value = ""
		exploit_categoria.value = ""
		exploit_extension.value = ""
		exploit_version.value = ""
	});

	/**
	 * Función que envia una peticion a la app para crear/editar un exploit
	 */ 
	button_add__exploits.addEventListener("click", async function(){

		let opcion = "";
		let nombre = document.querySelector("#exploit_name").value;
		let contenido_exploit = document.querySelector("#contenido_exploit");
		let contenido_exploit_valor = document.getElementById("contenido_exploit_valor");
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

		let peticion;

		if (contenido_exploit.value != ""){
			contenido_exploit_valor.innerHTML = contenido_exploit.value.split("\\")[2]
			contenido_exploit = await file_upload(contenido_exploit.files[0])
			
		} else {
			contenido_exploit = ""
		}
		
		if (opcion === "software"){
			peticion = {
				"exploit":nombre,
				"contenido":contenido_exploit,
				"extension":tecnologia,
				"cve":exploit_cve,
				"software":{
					"software_nombre":exploit_software,
					"software_version":exploit_software_version,
				}
			}
		} else {
			peticion = {
				"exploit":nombre,
				"contenido":contenido_exploit,
				"extension":tecnologia,
				"cve":exploit_cve,
				"cms":{
					"cms_nombre":exploit_cms,
					"cms_categoria":exploit_categoria,
					"cms_extension_nombre":exploit_extension,
					"cms_extension_version":exploit_version
				}
			}
		}

		if (opcion === "software" && peticion.software.software_nombre != "" && peticion.software.software_version != "") {
			send_json_fetch(server_url+"/exploits-crear", peticion);
		} else if (peticion.cms.cms_nombre != "" && peticion.cms.cms_categoria != "" && peticion.cms.cms_extension_nombre != "") {
			send_json_fetch(server_url+"/exploits-crear", peticion);
		}
		
		reload_site();
	});

	/**
	 * Función que envia una peticion a la app para eliminar un exploit
	 */ 
	button_exploits__borrar.addEventListener("click", function(){
		// POST - exploits-eliminar

		let value_select = document.querySelector("#exploit_name").value;
		if (value_select !== ""){
			peticion = {
				"exploit":value_select
			}
	
			console.log(peticion);
	
			send_json_fetch(server_url+"/exploits-eliminar", peticion);
	
			reload_site();
		}
	});

	/**
	 * Loading info
	 */ 
	set_maxdate();
	// Función async

	/**
	 * Peticiones al backend
	 */

	// ************************************************************************************************
	// ************************************************************************************************
	// ************************************************************************************************
	// ************************************************************************************************
	// POST - ejecucion

	/**
	 * Función que realiza la recoleccion de datos para la ejecucion del analisis
	 */
	scan__start.addEventListener("click", async function(){

		let sitio = document.querySelector(".scan__url").value;
		let archivo = document.querySelector(".scan__file");
		let fecha = document.querySelector("#next_scan").value
		let puertos = document.querySelector("#modulos_puertos").value;
		let cookie = document.querySelector("#modulos_cookie").value;
		let profundidad = document.querySelector("#profundidad").value;
		let redireccionamiento = document.querySelector("#redireccionamiento").checked;
		let lista_negra = document.querySelector("#lista_negra").value;
		let array_lista_negra = [];

		// Cada nueva línea será un elemento del array
		lista_negra = lista_negra.split('\n');
		
		lista_negra.forEach(element => {
			array_lista_negra.push(element);
		});
		
		if (archivo.value != ""){
			archivo = await file_upload(archivo.files[0])
		} else {
			archivo = ""
		}

		let peticion = {
			"sitio":sitio,
			"fecha":fecha,
			"archivo":archivo,
			"puertos":{
				"inicio":1,
				"final":puertos
			},
			"cookie":cookie,
			"profundidad":profundidad,
			
			"redireccionamiento":redireccionamiento,
			"lista_negra":array_lista_negra
		}
		console.log(peticion)
		send_json_fetch(server_url+"/ejecucion", peticion);

		reload_site();
	});

	// ************************************************************************************************
	// ************************************************************************************************
	// ************************************************************************************************
	// ************************************************************************************************
	// POST - consulta-volcado
	// Variable global
	json_consultas;

	/**
	 * Función que obtiene los reportes de la app 
	 */
	function start_consulta() {
		
		send_json_fetch(server_url+"/consulta-volcado", {})
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
				array_sites.forEach(element => {
					modulos__select.add(new Option(element, element));
				});
				json_consultas = json_respuesta;
			}
		)
	}

	// ************************************************************************************************
	// ************************************************************************************************
	// ************************************************************************************************
	// ************************************************************************************************
	// POST - exploits-volcado
	// Variable global
	json_consultas_exploits;

	/**
	 * Función que obtiene todos los nombres de los exploits 
	 */
	function start_consulta_exploits() {
		send_json_fetch(server_url+"/exploits-volcado", {})
		.then(
			json_respuesta =>{
				let array_exploits = [];

				let exploits__select = document.querySelector(".exploits__select");
				let exploits = json_respuesta.exploits;
				if (exploits !== undefined){
					exploits.forEach(element => {
						array_exploits.push(element.exploit);
					});
			
					array_exploits = [...new Set(array_exploits)];
			
					exploits__select.innerHTML = "";
					
					array_exploits.forEach(element => {
						exploits__select.add(new Option(element, element));
					});
					json_consultas_exploits = json_respuesta;
				}
			}
		)
	}

	json_proximos_escaneos;

	/** 
	 * Función que obtiene los proximos escaneos 
	 */
	function start_proximos_escaneos() {
		send_json_fetch(server_url+"/proximos-escaneos", {})
		.then(
			json_respuesta =>{
				json_proximos_escaneos = json_respuesta;
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

	/**
	 * Función que lanza la creacion de forma dinamica los reportes individuales
	 */ 
	button_consultas__opciones__proximo.addEventListener("click", function(){
		let value_select = document.querySelector(".modulos__select").value;
		load_sites(value_select);
	});

});

/**
 * Global configs
 */

// Función para enviar los datos en un json
const server_url = "http://localhost:3000";

/**
 * General Functions 
 */

/**
 * Función que restringe la fecha máxima
 */
function set_maxdate() {
	document.querySelector("#next_scan").min = new Date(new Date().getTime() - new Date().getTimezoneOffset() * 60000).toISOString().split("T")[0];
}

/**
 * Función que se encarga de hacer las peticiones
 */
async function send_json_fetch(url, json){
	let response = await (async () => {
		const rawResponse = await fetch(url, {
			method: 'POST', // *GET, POST, PUT, DELETE, etc.
			mode: 'cors', // no-cors, *cors, same-origin
			cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
			credentials: 'same-origin', // include, *same-origin, omit
			headers: {
			'Content-Type': 'application/json'
			},
			redirect: 'follow', // manual, *follow, error
			referrerPolicy: 'no-referrer', // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
			body: JSON.stringify(json) // body data type must match "Content-Type" header
		});
		const content = await rawResponse.json();
		return content;
	})();
	if (response.status !== undefined){
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
	}
	return response; // parses JSON response into native JavaScript objects
}

/** 
 * Función que obtiene en memoria el contenido del archivo
 */ 
function file_upload(file) {
	return new Promise((resolve, reject)=>{
		var reader = new FileReader();
		reader.onloadend = function () {
			resolve(reader.result);
		}
		reader.onerror = reject;
		reader.readAsDataURL(file);	
	})
}

/**
 * Funcion que se encarga de la creación de los recuadros de reportes
 */
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
		send_json_fetch(server_url+"/consulta-reporte", {"sitio":site,"fecha":date})
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
		send_json_fetch(server_url+"/reporte-eliminar", {"sitio":site,"fecha":date})
		reload_site()
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

/**
 * Funcion que actualiza la página
 */
async function reload_site(){
	await sleep(2000);
	window.location.reload()
}

/**
 * Funcion que asgina el nombre del archivo exploit al label que simula el botón
 */
function update_file_value(input){
	let contenido_exploit_valor = document.getElementById("contenido_exploit_valor");
	contenido_exploit_valor.innerHTML = input.value.split("\\")[2]
}

/**
 * Funcion que duerme al sistema 2 seg
 */
function sleep(ms) {
	return new Promise(resolve => setTimeout(resolve, ms));
}