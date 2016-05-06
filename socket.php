<?php
/*
  Fitxer socket.  
*/
    include 'funcions.php';

//Creació del socket.
$socket = socket_create(AF_INET , SOCK_RAW , SOL_TCP); 

capturar($socket,$conn,$taula);

?>