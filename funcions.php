<?php

//Connexió a la BD phpmon i nom de la taula.
$config = parse_ini_file('config.ini');
$conn=(connectar($config));
$taula = "paquet";

/*
    Funcions.
*/
function connectar($config)
{
    $conn = mysqli_connect("127.0.0.1", $config['username'], $config['password'], $config['dbname']);

    if (!$conn) {
        echo "Error " . mysqli_connect_errno() . ": " . mysqli_connect_error();
        exit;
    }
    return $conn;
}
/*
    Funció per crear la taula.
*/
function crearTaula($conn,$taula)
{
    $sql = 'CREATE TABLE '."$taula".' (
    ip_ver VARCHAR(20) NOT NULL,
    ip_len VARCHAR(20) NOT NULL,
    tos VARCHAR(20) NOT NULL,
    tot_len INTEGER(20) NOT NULL,
    identification VARCHAR(20) NOT NULL, 
    frag_off VARCHAR(20) NOT NULL,
    ttl VARCHAR(20) NOT NULL,
    protocol VARCHAR(20) NOT NULL,
    ip_checksum VARCHAR(20) NOT NULL,
    source_add VARCHAR(20) NOT NULL,
    dest_add VARCHAR(20) NOT NULL,
    source_port VARCHAR(20) NOT NULL,
    dest_port VARCHAR(20) NOT NULL,
    acknowledgement_number VARCHAR(20) NOT NULL,
    tcp_header_length VARCHAR(20) NOT NULL,
    tcp_flags VARCHAR(20) NOT NULL,
            cwr VARCHAR(20) NOT NULL,
            ecn VARCHAR(20) NOT NULL,
            urgent VARCHAR(20) NOT NULL,
            ack VARCHAR(20) NOT NULL,
            push VARCHAR(20) NOT NULL,
            reset VARCHAR(20) NOT NULL,
            syn VARCHAR(20) NOT NULL,
            fin VARCHAR(20) NOT NULL,
    window_size VARCHAR(20) NOT NULL,
    tcp_checksum VARCHAR(20) NOT NULL,
    date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )

    ;';
    //Crear la taula.
    if (mysqli_query($conn, $sql)) {
        echo "Taula $taula creada correctament";
    } else {
        echo  "Error creant la taula $taula: ".mysqli_error($conn)."\n";
    }
}

/*
    Funcio per esborrar la taula.
*/
function esborrarTaula($conn,$taula)
{
    $sql = "DROP TABLE $taula;";
    if (mysqli_query($conn, $sql)) {
        echo "Taula $taula esborrada correctament";
    } else {
        echo  "Error esborrant la taula $taula: ".mysqli_error($conn)."\n";
    }
}

/*
    Funció per inserir dades a la taula.
*/
function inserirDades($conn,$taula,$sniff)
{
    //Tractem l'array per extraure tots els valors.
    $valors=implode("','", $sniff);
    $sql=("INSERT INTO $taula VALUES ('$valors',NOW());");
    if (mysqli_query($conn,$sql)){
        echo "capturat\n";
    }   else{
        echo "No capturat\n";
    }     
}

/*
    Funció per mostrar les dades de la taula.
*/
function mostrarTaula($conn,$taula)
{
    $flag=true;
    $resultat=mysqli_query($conn, 'SELECT * FROM phpmon.paquet');

    while($registre= mysqli_fetch_assoc($resultat)){

    if($flag){
          $key = array_keys($registre);
          echo "<table border='1'>";
          echo "<tr>";
          foreach ($key as $cap) {
             echo "<th>" . $cap . "</th>";
          }
          echo "</tr>";
    $flag=false;
    }
        echo "<tr>";
        foreach ($registre as $camp){
            echo "<td>". $camp ."</td>";
        }
        echo "</tr>";
    }
    echo "</table>";

}

/*
    Funció per capturar paquets.
*/
function capturar($socket,$conn,$taula,$ip)
{ 
    $ip='192.168.202.247';
    if($socket)
    {
        echo "Starting sniffing...\n";
        while(true)
        {
            //Start receiving on the raw socket
            socket_recv ( $socket , $buf , 65536 , 0 );
                 
            //Process the packet
            $sniff=process_packet($buf,$conn,$taula);
            if ($sniff['source_port']!='3306' && $sniff['dest_port']!='3306')
            {
                if ($sniff['source_add'] ==$ip && $sniff['dest_add'] == $ip)
                {
                
                } else
                {
                    inserirDades($conn,$taula,$sniff);
                }
            }
        }
    }
     
    //Some error - check that you used sudo !!
    else
    {
        $error_code = socket_last_error();
        $error_message = socket_strerror($error_code);  
         
        echo "Could not create socket : [$error_code] $error_message";
    }
}

/*
    Funció per encendre tcpdump.
*/

/*
    Funció per processar paquets.
*/
function process_packet($packet)
{
    //IP Header
    $ip_header_fmt = 'Cip_ver_len/'
    .'Ctos/'
    .'ntot_len/'
    .'nidentification/'
    .'nfrag_off/'
    .'Cttl/'
    .'Cprotocol/nheader_checksum/Nsource_add/Ndest_add/';
       
    //Desempaquetar la capçalera IP.
    $ip_header = unpack($ip_header_fmt , $packet);
   
    if($ip_header['protocol'] == '6' )
    {
        return print_tcp_packet($packet,$conn,$taula);
    }
}
 
/*
  Processar paquet tcp.
*/
function print_tcp_packet($packet,$conn,$taula)
{
    $ip_header_fmt = 'Cip_ver_len/'
    .'Ctos/'
    .'ntot_len/';
     
    $p = unpack($ip_header_fmt , $packet);
    $ip_len = ($p['ip_ver_len'] & 0x0F);
     
    if($ip_len == 5)
    {
         
        //Format per desempaquetar de la capçalera IP.
        $ip_header_fmt = 'Cip_ver_len/'
        .'Ctos/'
        .'ntot_len/'
        .'nidentification/'
        .'nfrag_off/'
        .'Cttl/'
        .'Cprotocol/'
        .'nip_checksum/'
        .'Nsource_add/'
        .'Ndest_add/';
    }
    else if ($ip_len == 6)
    {
        //Format per desempaquetar de la capçalera IP.
        $ip_header_fmt = 'Cip_ver_len/'
        .'Ctos/'
        .'ntot_len/'
        .'nidentification/'
        .'nfrag_off/'
        .'Cttl/'
        .'Cprotocol/'
        .'nip_checksum/'
        .'Nsource_add/'
        .'Ndest_add/'
        .'Noptions_padding/';
    }
     
    $tcp_header_fmt = 'nsource_port/'
    .'ndest_port/'
    .'Nsequence_number/'
    .'Nacknowledgement_number/'
    .'Coffset_reserved/';
     
    //Format total del paquet amb les capçaleres.
    $total_packet = $ip_header_fmt.$tcp_header_fmt;
     
    $p = unpack($total_packet , $packet);
    $tcp_header_len = ($p['offset_reserved'] >> 4);
     
    if($tcp_header_len == 5)
    {
        //Format de la capçalera TCP per desempaquetar.
        $tcp_header_fmt = 'nsource_port/'
        .'ndest_port/'
        .'Nsequence_number/'
        .'Nacknowledgement_number/'
        .'Coffset_reserved/'
        .'Ctcp_flags/'
        .'nwindow_size/'
        .'nchecksum/'
        .'nurgent_pointer/';
    }
    else if($tcp_header_len == 6)
    {
        //Format capçalera TCP per desempaquetar.
        $tcp_header_fmt = 'nsource_port/'
        .'ndest_port/'
        .'Nsequence_number/'
        .'Nacknowledgement_number/'
        .'Coffset_reserved/'
        .'Ctcp_flags/'
        .'nwindow_size/'
        .'nchecksum/'
        .'nurgent_pointer/'
        .'Ntcp_options_padding/';
    }
     
    //Paquet total amb data desempaquetada.
    $total_packet = $ip_header_fmt.$tcp_header_fmt;
     
    //Desempaquetar el paquet.
    $packet = unpack($total_packet , $packet);
     
    //Preparar les dades desempaquetades.
    $sniff = array(
        //Capçalera IP.
            'ip_ver' => ($packet['ip_ver_len'] >> 4) ,
            'ip_len' => ($packet['ip_ver_len'] & 0x0F) ,
            'tos' => $packet['tos'] ,
            'tot_len' => $packet['tot_len'] ,
            'identification' => $packet['identification'] ,
            'frag_off' => $packet['frag_off'] ,
            'ttl' => $packet['ttl'] ,
            'protocol' => $packet['protocol'] ,
            'ip_checksum' => $packet['ip_checksum'] ,
            'source_add' => long2ip($packet['source_add']) ,
            'dest_add' => long2ip($packet['dest_add']) ,
   	//Capçalera TCP.
            'source_port' => $packet['source_port'] ,
            'dest_port' => $packet['dest_port'] ,
            'sequence_number' => $packet['sequence_number'] ,
            'acknowledgement_number' => $packet['acknowledgement_number'] ,
            'tcp_header_length' => ($packet['offset_reserved'] >> 4) ,
            //Flags TCP.
                'cwr' => (($packet['tcp_flags'] & 0x80) >> 7) ,
                'ecn' => (($packet['tcp_flags'] & 0x40) >> 6) ,
                'urgent' => (($packet['tcp_flags'] & 0x20) >> 5 ) ,
                'ack' => (($packet['tcp_flags'] & 0x10) >>4) ,
                'push' => (($packet['tcp_flags'] & 0x08)>>3) ,
                'reset' => (($packet['tcp_flags'] & 0x04)>>2) ,
                'syn' => (($packet['tcp_flags'] & 0x02)>>1) ,
                'fin' => (($packet['tcp_flags'] & 0x01)) ,
            'window_size' => $packet['window_size'] ,
            'tcp_checksum' => $packet['checksum'] . ' [0x'.dechex($packet['checksum']).']',
    );
 
    //retornar les dades desempaquetades.
    return $sniff;
}

?>