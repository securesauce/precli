import System.IO.Unsafe

value :: String
value = unsafePerformIO $ readFile "/etc/passwd"
