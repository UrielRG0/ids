#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <algorithm>
#include <cstdlib>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <map>
#include <chrono>
#include <netdb.h>
#include <cstring>
#include <netinet/ip6.h>
#include <iomanip>
#include <ctime>
#include <sstream>
#include <termios.h>
#include <unistd.h>
#include <sys/select.h>
#include <cstdlib>

#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/screen.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>

using namespace std;
using namespace ftxui;



				//[1]
mutex mtx;
vector<string> whitelist;
map<string, string> blacklist;
vector<string> ultimas_alertas;
vector<string> bitacora_sitios;
map<string, chrono::steady_clock::time_point> ultimo_correo_enviado;
string admin_email = "correo_predeterminado@red.com";
string prefijo_red="192.168";
int paquetes_procesados = 0;
map<string,string> cache_dns;


			//[2]
void cargar_env() {
    ifstream file(".env");
    string linea;
    while (getline(file, linea)) {
        if (linea.find("ADMIN_EMAIL=") != string::npos) {
            admin_email = linea.substr(linea.find("=") + 1);
        }
        if(linea.find("RED_LOCAL=") != string::npos){
        	prefijo_red = linea.substr(linea.find("=")+1);
        }
    }
}


				//[3]
string obtener_hora_actual(){
	auto t=time(nullptr);
	auto tm=*localtime(&t);
	ostringstream oss;
	oss<<put_time(&tm, "%Y-%m-%d %H:%M:%S");
	return oss.str();
}

				//[4]
void cargar_listas() {
    whitelist.clear();
    ifstream w_file("whitelist.txt");
    string ip;
    while (w_file >> ip) {
        whitelist.push_back(ip);
    }

    blacklist.clear();
    ifstream b_file("blacklist.txt");
    string linea;
    while (getline(b_file, linea)) {
        if (linea.empty()) continue;
        size_t coma = linea.find(',');
        if (coma != string::npos) {
            string ip_maliciosa = linea.substr(0, coma);
            string riesgo = linea.substr(coma + 1);
            blacklist[ip_maliciosa] = riesgo; 
        } else {
            blacklist[linea] = "Malware Genérico";
        }
    }
}

								//[5]
void enviar_alerta(string tipo, string ip_sospechosa) {
    string riesgo_formateado = "Riesgo: Amenaza No Clasificada";
    if (tipo.find("MALWARE_BLACKLIST:") != string::npos) {
        riesgo_formateado = "Riesgo: " + tipo.substr(tipo.find(":") + 1);
        tipo = "MALWARE_BLACKLIST";
    }

    mtx.lock();
    string mensaje = "[" + obtener_hora_actual() + "] [ALERTA] " + tipo + " (" + riesgo_formateado + ") en IP: " + ip_sospechosa;

    ultimas_alertas.insert(ultimas_alertas.begin(), mensaje);
    if(ultimas_alertas.size() > 10) ultimas_alertas.pop_back();

    auto ahora = chrono::steady_clock::now();
    bool mandar_correo = true;

    if (ultimo_correo_enviado.count(ip_sospechosa)) {
        auto segundos_pasados = chrono::duration_cast<chrono::seconds>(ahora - ultimo_correo_enviado[ip_sospechosa]).count();
        if (segundos_pasados < 60) {
            mandar_correo = false; 
        }
    }

    if (mandar_correo) {
        ultimo_correo_enviado[ip_sospechosa] = ahora;
    }
    mtx.unlock();

    if (mandar_correo) {
        string datos_extra = mensaje;

        if (tipo == "MALWARE_BLACKLIST") {
            string comando_forense = "echo '--- CLASIFICACIÓN ---' > temp_forense.txt; "
                                     "echo '" + riesgo_formateado + "' >> temp_forense.txt; "
                                     "echo '\n--- GEOLOCALIZACIÓN Y HOSTING (ipinfo) ---' >> temp_forense.txt; "
                                     "curl -s ipinfo.io/" + ip_sospechosa + " >> temp_forense.txt; "
                                     "echo '\n--- DATOS DE LA RED (ip.guide) ---' >> temp_forense.txt; "
                                     "curl -sL ip.guide/" + ip_sospechosa + " >> temp_forense.txt; "
                                     "echo '\n--- CONTACTO DE ABUSO PARA REPORTE (WHOIS) ---' >> temp_forense.txt; "
                                     "whois " + ip_sospechosa + " | grep -i 'abuse' | head -n 3 >> temp_forense.txt";
            
            system(comando_forense.c_str());
            ifstream forense_file("temp_forense.txt");
            string linea;
            datos_extra += "\n\n========== REPORTE FORENSE AUTOMATIZADO ==========\n";
            while (getline(forense_file, linea)) {
                datos_extra += linea + "\n";
            }
            datos_extra += "==================================================\n";
        }

        string comando_py = "python correo.py '" + tipo + "' '" + datos_extra + "' &";
        system(comando_py.c_str());
    }
}

   

			
							//[6]
string obtener_dominio(string ip, int af_family) {
    if (cache_dns.count(ip)) return cache_dns[ip];

    char host[NI_MAXHOST];
    
    if (af_family == AF_INET) { 
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
        if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), NULL, 0, NI_NAMEREQD) == 0) {
            cache_dns[ip] = string(host);
            return string(host);
        }
    } 
    else if (af_family == AF_INET6) { 
        struct sockaddr_in6 sa6;
        memset(&sa6, 0, sizeof sa6);
        sa6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, ip.c_str(), &sa6.sin6_addr);
        if (getnameinfo((struct sockaddr*)&sa6, sizeof(sa6), host, sizeof(host), NULL, 0, NI_NAMEREQD) == 0) {
            cache_dns[ip] = string(host);
            return string(host);
        }
    }

    cache_dns[ip] = ip; 
    return ip; 
}


												//[7]
void procesar_paquete(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;

    mtx.lock();
    paquetes_procesados++;
    mtx.unlock();

    uint16_t eth_type = ntohs(eth_header->ether_type);
    string ip_origen = "";
    string ip_destino = "";
    int af_family = 0;

    if (eth_type == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        ip_origen = inet_ntoa(ip_header->ip_src);
        ip_destino = inet_ntoa(ip_header->ip_dst);
        af_family = AF_INET;
    } 
    else if (eth_type == ETHERTYPE_IPV6) {
        struct ip6_hdr *ipv6_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
        char src_str[INET6_ADDRSTRLEN];
        char dst_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ipv6_header->ip6_src), src_str, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), dst_str, INET6_ADDRSTRLEN);
        ip_origen = string(src_str);
        ip_destino = string(dst_str);
        af_family = AF_INET6;
    } 
    else {
        return;
    }

    char mac_temp[18];
    sprintf(mac_temp, "%02x:%02x:%02x:%02x:%02x:%02x",
            eth_header->ether_shost[0], eth_header->ether_shost[1],
            eth_header->ether_shost[2], eth_header->ether_shost[3],
            eth_header->ether_shost[4], eth_header->ether_shost[5]);
    string mac_origen = string(mac_temp);

    if (ip_origen.find(prefijo_red) != string::npos) {
        bool ip_autorizada = (find(whitelist.begin(), whitelist.end(), ip_origen) != whitelist.end());
        bool mac_autorizada = (find(whitelist.begin(), whitelist.end(), mac_origen) != whitelist.end());

        if (!ip_autorizada && !mac_autorizada) {
            enviar_alerta("INTRUSO_NO_AUTORIZADO", ip_origen + " (MAC: " + mac_origen + ")");
        }
    }

        if (blacklist.count(ip_destino)) {
            string riesgo_detectado = blacklist[ip_destino]; 
            enviar_alerta("MALWARE_BLACKLIST:" + riesgo_detectado, ip_destino);
        }

    if (ip_destino.find(prefijo_red) == string::npos) { 

        if (ip_destino != "255.255.255.255" &&
            ip_destino.find("224.0.0.") == string::npos &&
            ip_destino.find("239.255.") == string::npos &&
            ip_destino.find("ff02::") == string::npos) {

            string dominio = obtener_dominio(ip_destino, af_family);

            lock_guard<mutex> lock(mtx);
            string bitacora = "["+obtener_hora_actual()+"] Tráfico a: " + dominio; 

            if (find(bitacora_sitios.begin(), bitacora_sitios.end(), bitacora) == bitacora_sitios.end()) {
                bitacora_sitios.insert(bitacora_sitios.begin(), bitacora);
                if(bitacora_sitios.size() > 10) bitacora_sitios.pop_back();

                ofstream log_file("reporte_trafico.log", ios_base::app);
                log_file << bitacora << " (IP: " << ip_destino << ")" << endl;
            }
        }
    }
}
    
					//[8]
void iniciar_sniffer(string dev) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle != NULL) {
        pcap_loop(handle, 0, procesar_paquete, NULL);
    }
}


						//[9]
void configurar_terminal(bool habilitar) {
    static struct termios oldt, newt;
    if (habilitar) {
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~(ICANON | ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        std::cout << "\033[?25l"; 
    } else {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        std::cout << "\033[?25h";
    }
}

			//[10]
bool kbhit() {
    struct timeval tv = { 0L, 0L };
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    return select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) > 0;
}

				//[11]
void mostrar_intro_retro() {
    configurar_terminal(true);
    
    int pulsaciones = 0;
    bool mostrar_pista_skip = false;

    auto evaluar_skip = [&]() -> bool {
        if (kbhit()) {
            char c = getchar();
            pulsaciones++;
            if (pulsaciones == 1) {
                mostrar_pista_skip = true;
            } else if (pulsaciones >= 2) {
                return true;
            }
        }
        return false;
    };

    int pasos_carga = 50;
    int ms_por_paso = 5000 / pasos_carga;

    for (int i = 0; i <= pasos_carga; i++) {
        std::cout << "\033[H\033[J";
        std::cout << "\n\n\n\n\n\n\n\n\n\n"; 

        int porcentaje = (i * 100) / pasos_carga;
        std::string barra = "[";
        for (int j = 0; j < pasos_carga; j++) {
            if (j < i) barra += "\033[38;5;46m█\033[0m"; 
            else barra += "\033[38;5;235m.\033[0m";      
        }
        barra += "]";
        std::cout << "               Starting IDS....\n\n";
        std::cout << "               " << barra << " " << porcentaje << "%\n\n";

        if (mostrar_pista_skip) {
            std::cout << "               \033[38;5;238m[ Press any key to skip... ]\033[0m\n";
        }

        std::cout << std::flush;

        auto inicio = std::chrono::steady_clock::now();
        while (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - inicio).count() < ms_por_paso) {
            if (evaluar_skip()) {
                configurar_terminal(false);
                system("clear");
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    std::vector<std::string> logo = {
        " _____  ____   ____    ___  _   _  ____  _____  ___  _____  _   _   ___  ___   ___   _   _   __   _     ",
        "|_   _||  _ \\ / ___|  |_ _|| \\ | |/ ___||_   _||_ _||_   _|| | | | / __||_ _| / _ \\ | \\ | | /  \\ | |    ",
        "  | |  | | | |\\___ \\   | | |  \\| |\\___ \\  | |   | |   | |  | | | || |    | | | | | ||  \\| |/ /\\ \\| |    ",
        " _| |_ | |_| | ___) |  | | | |\\  | ___) | | |   | |   | |  | |_| || |___ | | | |_| || |\\  / ____ \\ |___ ",
        "|_____||____/ |____/  |___||_| \\_||____/  |_|  |___|  |_|   \\___/  \\____|___| \\___/ |_| \\_/_/    \\_\\_____|"
    };

    std::vector<std::string> colores_animacion = {
        "\033[38;5;16m", "\033[38;5;232m", "\033[38;5;235m", "\033[38;5;22m", 
        "\033[38;5;28m", "\033[38;5;34m", "\033[38;5;40m", "\033[38;5;46m", 
        "\033[38;5;46m", "\033[38;5;46m", "\033[38;5;46m", "\033[38;5;46m",
        "\033[38;5;40m", "\033[38;5;34m", "\033[38;5;28m", "\033[38;5;22m", 
        "\033[38;5;235m", "\033[38;5;232m", "\033[38;5;16m", "\033[38;5;16m"
    };

    int cuadros_totales = colores_animacion.size();
    int ms_por_cuadro = 250; 

    for (int i = 0; i < cuadros_totales; i++) {
        std::cout << "\033[H\033[J"; 
        std::cout << "\n\n\n\n\n\n\n\n";
        
        for (const std::string& linea : logo) {
            std::cout << "               " << colores_animacion[i] << linea << "\033[0m\n";
        }
        std::cout << "\n\n";
        
        if (mostrar_pista_skip) {
            std::cout << "               \033[38;5;238m[ Press any key to skip.... ]\033[0m\n";
        }

        std::cout << std::flush;
        auto inicio = std::chrono::steady_clock::now();
        while (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - inicio).count() < ms_por_cuadro) {
            if (evaluar_skip()) {
                configurar_terminal(false);
                system("clear");
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    configurar_terminal(false);
    system("clear");
}

							//[12]
bool validar_sudo(const std::string& password) {
    std::string cmd = "echo '" + password + "' | sudo -k -S -v 2>/dev/null";
    int resultado = system(cmd.c_str());
    return (resultado == 0); 
}
							//[13]


int mostrar_menu_principal(int& nivel_acceso) {
    auto screen = ScreenInteractive::Fullscreen();
    int accion_elegida = 0;
    int tab_index = 0;
    int seleccion_principal = 0;
    int seleccion_admin = 0;

    std::string input_password = "";
    bool auth_error = false;
    bool permiso_denegado = false; // Mensaje si un Operador intenta tocar el .env

    std::vector<std::string> opciones_principal = {
        "Start IDS",
        "Configurations",
        "Exit of the IDS"
    };

    MenuOption config_principal;
    config_principal.on_enter = [&] {
        if (seleccion_principal == 0) { accion_elegida = 1; screen.ExitLoopClosure()(); }
        if (seleccion_principal == 1) {
            if (nivel_acceso > 0) {
                tab_index = 2; // Si ya tiene algún rol, entra directo
            } else {
                tab_index = 1;
                input_password = "";
                auth_error = false;
            }
        }
        if (seleccion_principal == 2) { accion_elegida = 0; screen.ExitLoopClosure()(); }
    };
    Component menu_principal = Menu(&opciones_principal, &seleccion_principal, config_principal);

    InputOption pass_option;
    pass_option.password = true;
    Component input_login = Input(&input_password, "Write the sudo password....", pass_option);

    Component boton_login = Button("Sudo Authentication", [&] {
        std::string pass_limpia = input_password;
        pass_limpia.erase(pass_limpia.find_last_not_of(" \n\r\t") + 1);

        if (validar_sudo(pass_limpia)) {
            nivel_acceso = 2; // ROL 2: SUPERUSUARIO
            tab_index = 2;
            auth_error = false;
            input_password = "";
        } else {
            auth_error = true;
            input_password = "";
        }
    });

    // NUEVO BOTÓN: ROL DE OPERADOR
    Component boton_sin_sudo = Button("Enter without Sudo (Restricted Mode)", [&] {
        nivel_acceso = 1; // ROL 1: OPERADOR (Solo Whitelist y Blacklist)
        tab_index = 2;
        auth_error = false;
        input_password = "";
    });

    Component formulario_login = Container::Vertical({
        input_login,
        boton_login,
        boton_sin_sudo
    });

    std::vector<std::string> opciones_admin = {
        "Edit Whitelist",
        "Edit Blacklist",
        "Edit .env",
        "Go back"
    };

    MenuOption config_admin;
    config_admin.on_enter = [&] {
        permiso_denegado = false; // Limpiamos la alerta al movernos
        if (seleccion_admin == 0) { accion_elegida = 2; screen.ExitLoopClosure()(); }
        if (seleccion_admin == 1) { accion_elegida = 3; screen.ExitLoopClosure()(); }
        if (seleccion_admin == 2) { 
            // AQUÍ ESTÁ LA MAGIA DE LA AUTORIZACIÓN (RBAC)
            if (nivel_acceso == 2) {
                accion_elegida = 4; 
                screen.ExitLoopClosure()(); 
            } else {
                permiso_denegado = true; // Rebota al usuario nivel 1
            }
        }
        if (seleccion_admin == 3) { tab_index = 0; seleccion_admin = 0; }
    };
    Component menu_admin = Menu(&opciones_admin, &seleccion_admin, config_admin);

    auto contenedor_tabs = Container::Tab({menu_principal, formulario_login, menu_admin}, &tab_index);
    auto renderizador = Renderer(contenedor_tabs, [&] {
        Element contenido_central;

        if (tab_index == 0) {
            contenido_central = window(text(" Main Menu ") | bold | hcenter, menu_principal->Render() | hcenter);
        }
        else if (tab_index == 1) {
            contenido_central = window(text(" Sudo Authentication Required ") | bold | color(Color::Red) | hcenter,
                vbox({
                    text("Put the sudo password to access full privileges: ") | hcenter,
                    separatorEmpty(),
                    hbox({ text(" Password: "), input_login->Render() | border }) | hcenter,
                    separatorEmpty(),
                    boton_login->Render() | hcenter,
                    separatorEmpty(),
                    text("--- OR ---") | dim | hcenter,
                    separatorEmpty(),
                    boton_sin_sudo->Render() | hcenter,
                    separatorEmpty(),
                    auth_error ? text("Wrong password. Please try again....") | color(Color::Red) | blink | hcenter : text("")
                })
            );
        }
        else if (tab_index == 2) {
            contenido_central = window(text(" IDS Administration ") | bold | color(Color::Green) | hcenter, 
                vbox({
                    text(nivel_acceso == 2 ? "Status: ROOT ADMIN" : "Status: RESTRICTED OPERATOR") | bold | hcenter,
                    separator(),
                    menu_admin->Render() | hcenter,
                    separatorEmpty(),
                    permiso_denegado ? text("ACCESO DENEGADO. Requiere permisos Sudo.") | color(Color::Red) | blink | hcenter : text("")
                })
            );
        }

        return vbox({
            text("=========================================") | bold | hcenter | color(Color::Blue),
            text("           Institucional IDS            ")  | bold | hcenter | color(Color::Cyan),
            text("=========================================") | bold | hcenter | color(Color::Blue),
            separatorEmpty(),
            separatorEmpty(),
            contenido_central | borderRounded | color(Color::White) | hcenter,
            filler(),
            text("Use the keys [↑] [↓] for navigate, [TAB] for change, and [ENTER] for select.") | dim | hcenter
        });
    });

    screen.Loop(renderizador);
    return accion_elegida;
}



		//[14]
int main() {
    cargar_env();
    cargar_listas();

    mostrar_intro_retro();

    // Bandera de seguridad para no duplicar el motor en la red
    bool sniffer_iniciado = false; 
    
    // Nivel de Acceso RBAC: 0 (Nada), 1 (Operador Restringido), 2 (Root/Sudo)
    int nivel_acceso = 0; 

    while (true) {
        // Le pasamos el nivel de acceso al menú para que decida qué permisos darte
        int accion = mostrar_menu_principal(nivel_acceso);

        if (accion == 0) {
            return 0; // Apaga el programa completo
        }
        else if (accion == 1) {
            system("stty sane");
            system("clear");

            // 1. ARRANCAMOS EL MOTOR SOLO LA PRIMERA VEZ
            if (!sniffer_iniciado) {
                thread sniffer_thread(iniciar_sniffer, "enp0s3");
                sniffer_thread.detach(); // Se queda vigilando la red en el fondo
                sniffer_iniciado = true;
            }

            // 2. CREAMOS LA INTERFAZ DEL ESCÁNER
            auto screen_scanner = ScreenInteractive::Fullscreen();
            std::atomic<bool> ui_activa(true);

            // 3. BOTÓN PARA REGRESAR AL MENÚ
            Component btn_regresar = Button("Detener Visualización y Regresar al Menú", [&] {
                ui_activa = false;
                screen_scanner.ExitLoopClosure()();
            });

            auto contenedor_scanner = Container::Vertical({ btn_regresar });

            // 4. RENDERIZADO VISUAL DEL ESCÁNER
            auto render_scanner = Renderer(contenedor_scanner, [&] {
                Elements ui_alertas;
                Elements ui_bitacora;

                mtx.lock();
                for (const auto& al : ultimas_alertas) ui_alertas.push_back(text(al) | color(Color::Red));
                for (const auto& bit : bitacora_sitios) ui_bitacora.push_back(text(bit) | color(Color::Cyan));
                int total_pkts = paquetes_procesados;
                mtx.unlock();

                if (ui_alertas.empty()) ui_alertas.push_back(text("Sin amenazas detectadas..."));
                if (ui_bitacora.empty()) ui_bitacora.push_back(text("Esperando tráfico web..."));

                return vbox({
                    text(" SISTEMA IDS INSTITUCIONAL ") | bold | hcenter | bgcolor(Color::Blue),
                    separator(),
                    hbox({
                        text(" Admin: " + admin_email) | bold,
                        filler(),
                        text(" Paquetes Leídos: " + to_string(total_pkts)) | color(Color::Yellow),
                    }),
                    separator(),
                    hbox({
                        window(text(" ALERTAS DE EMERGENCIA "), vbox(ui_alertas)) | flex,
                        window(text(" BITÁCORA DE SITIOS VISTOS "), vbox(ui_bitacora)) | flex,
                    }),
                    separatorEmpty(),
                    btn_regresar->Render() | hcenter
                }) | border;
            });

            // 5. HILO DE REFRESCO
            thread refresh_ui([&] {
                while (ui_activa) {
                    this_thread::sleep_for(chrono::milliseconds(100));
                    screen_scanner.PostEvent(Event::Custom);
                }
            });

            screen_scanner.Loop(render_scanner);

            // Limpiamos el hilo de refresco antes de volver al menú
            refresh_ui.join(); 
        }
        else if (accion == 2) {
            system("stty sane");
            system("clear");
            system("nano whitelist.txt");
            cargar_listas();
        }
        else if (accion == 3) {
            system("stty sane");
            system("clear");
            system("nano blacklist.txt");
            cargar_listas();
        }
        else if (accion == 4) {
            system("stty sane");
            system("clear");
            // Se invoca sudo nano porque el archivo está protegido por root a nivel sistema
            system("sudo nano .env"); 
            cargar_env();
        }
    }

    return 0;
}
