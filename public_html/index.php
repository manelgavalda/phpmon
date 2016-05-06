<html>
  <head>
    <title> Monitorització PHP Manel </title>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
  </head>
  <body>
    <form method="post">
    <h1>Funcionalitat socket</h1>
      <p>
        <button name="start">Start</button>
        <button name="stop">Stop</button>
        <button name="status">Status</button>
      </p>
      <h1>Tcpdump</h1>
        <p>
          <button name="tcpdump">Tcpdump</button>
        </p>
    <h1>Funcionalitat bd</h1>
      <p>
        <button name="crearTaula">Crear Taula</button>
        <button name="esborrarTaula">Borrar Taula</button>
  
        <button name="mostrarTaula">Mostrar Taula</button>
      </p>
    <h1>Pàgines consultes</h1>
      <p>
        <button name="consultes" formaction="consultes.php">Pàgina consultes</button>
      </p>
    </form>
  </body>
</html>

<?php
// Include del fitxer de funcions.
include '../funcions.php';

/*
  Botons Start, stop, status del servei socket.
*/
if (isset($_POST['start']))
{
    $output=shell_exec("sudo /etc/init.d/socket start");
    echo "<pre>$output</pre>";
}

if (isset($_POST['stop']))
{
  $output=shell_exec("sudo /etc/init.d/socket stop");
    echo "<pre>$output</pre>";
}

if (isset($_POST['status']))
{
  $output=shell_exec("sudo /etc/init.d/socket status");
    echo "<pre>$output</pre>";
}
/*
  tcpdump
*/
if (isset($_POST['tcpdump']))
{
  shell_exec("ps aux | grep -i tcpdump | grep -v grep > /dev/null 2> /dev/null $?",$return_var);
  echo $return_var;
  if ("$?"== "1" )
  {
    shell_exec("sudo /usr/sbin/tcpdump > /dev/null 2> /dev/null &");
    echo "Corrent ($!)";
  }
  else
  {
    echo "El servei ja esta corrent";
  }
}

if (isset($_POST['tcpdumpo']))
{
  $output=shell_exec("sudo killall tcpdump");
  echo "<pre>$output</pre>";
}

/*
  Botons per gestionar la taula on guardarem les dades
*/
if (isset($_POST['crearTaula']))
{
  crearTaula($conn,$taula);
}

if (isset($_POST['esborrarTaula']))
{
  esborrarTaula($conn,$taula);
}
if (isset($_POST['mostrarTaula']))
{
  mostrarTaula($conn,$taula);
}
?>
