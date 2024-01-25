<div>
    <h1 style="font-family:monospace; color:red;">AclChecker</h1>
</div>
<div class="ver; color:red;">Version 0.9 Beta</div>

<div>
    <?php

    if( isset($_POST['submit']) )
    {
        //be sure to validate and clean your variables
        $protocol = htmlentities($_POST['protocol']);
        $src = htmlentities($_POST['src']);
        $dst = htmlentities($_POST['dst']);
        $dport = htmlentities($_POST['dport']);
        $gw = htmlentities($_POST['gw']);
        $vrf = htmlentities($_POST['vrf']);
    
    }

    // system("./ac2-web.py -r $protocol -s $src -d $dst -p $dport -g $gw $vrf 2>&1");

    
    $cmd = escapeshellcmd("./aclchecker_web_0.9.py -r $protocol -s $src -d $dst -p $dport -g $gw -v $vrf");

    $descriptorspec = array(
    0 => array("pipe", "r"),   // stdin is a pipe that the child will read from
    1 => array("pipe", "w"),   // stdout is a pipe that the child will write to
    2 => array("pipe", "w")    // stderr is a pipe that the child will write to
    );
    flush();
    print "<div class='command'>$protocol $src $dst $dport $gw $vrf</div>";
    $process = proc_open($cmd, $descriptorspec, $pipes, realpath('./'), array());
    echo "<pre>";
    if (is_resource($process)) {
        while ($s = fgets($pipes[1])) {
            print $s;
            flush();
        }
    }
    echo "</pre>";
   

    ?>
</div>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AclChecker</title>
    <link rel="stylesheet" href="css/style.css">
</head>

<body style="font-family:monospace">
    <div>
        <form action="" method="post">
            Protocol (tcp|udp|ip|icmp)<br>
            <input type="text" name="protocol" id="protocol"></input><br>
            Source IP<br>
            <input type="text" name="src" id="src"></input><br>
            Destination IP<br>
            <input type="text" name="dst" id="dst"></input><br>
            Destination port<br>
            <input type="text" name="dport" id="dport"></input><br>
            Gateway<br>
            <input type="text" name="gw" id="gw"></input><br>
            VRF on first hop (optional)<br>
            <input type="text" name="vrf" id="vrf" value='default'></input><br>
            <br>
    </div>    



    <div>   
        <button type="submit" name="submit" value="send">Run</button>
    </div>
        </form>
</body>
</html>