<?php
/** [LGPL] Copyright 2011-2013 Gima

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * Validates username and password combinations with local Kerberos's 'kinit'
 * executable (requires the local Kerberos installation to be configured
 * correctly).
 * Has been tested on cs.joensuu.fi and it authenticates successfully against
 * Itä-Suomen Yliopisto UEFAD Active Directory.
 * 
 * @author Gima
 */
class KInit {

    /**
     * Implementation
     * --------------
     * 
     * Since 'kinit' insists on writing the ticket to a file, it would be a
     * security vulnerability if the filesystem permissions allowed others
     * access to the file. And since the ticket is not needed (we are just
     * checking login credentials), it's written to '/dev/null'.
     *
     * The implementation then checks kinit's return messages to determine
     * whether the authentication attempt was successful or not.
     */

    /** kinit's process handle */
    private $process;

    /** kinit's stdin stream / write to this */
    private $stdin;

    /** kinit's stdout stream / read from here */
    private $stdout;

    /** kinit's stderr stream / read from here */
    private $stderr;

    /** kinit's exit code */
    private $exitcode = null;

    /**
     * Test if the supplied username and password combination is valid using
     * 'kinit' executable.
     *
     * @param  string  $username
     * @param  string  $password
     * @param  int  $delay  (in milliseconds)
     * @return boolean - True if combination was valid, false otherwise.
     */
    public static function auth($username, $password, $delay = 1000) {
        $start = microtime(true);

        $validInput = true;

        // ensure the username is not empty and consists of only valid characters
        if (@strlen($username) === 0) $validInput = false;
        if (@preg_match('/^[a-zA-Z0-9+-_\\.,@]*$/', $username) !== 1) $validInput = false;

        $success = false;

        if ($validInput) {
            $success = $this->_auth($username, $password);
            $this->_cleanup();
        }

        // sleep until $delay has passed from $start
        $sleep = ($delay*1000) - (microtime(true) - $start);
        if ($sleep >= 0) {
            usleep($sleep);
        }

        return $success;
    }

    /**
     * Perform the actual credentials check using 'kinit'.
     * 
     * @return boolean - True if credentials were valid, false otherwise.
     */
    private function _auth($username, $password) {

        $cmd = "kinit -l 1s -c /dev/null {$username}";
        /*
         * parameters
         * ----------
         * -l 1s          Request that the ticket to be valid for only 1 second
         * -c /dev/null"  Write the ticket to file /dev/null
         */

        /*
         * start the 'kinit' process and direct it's stdin, stdout and stderr
         * to php's side for reading and writing
         */
        $pipes = array();
    
        $this->process = proc_open(
            $cmd,
            array(
                0 => array('pipe', 'r'),
                1 => array('pipe', 'w'),
                2 => array('pipe', 'a'),
            ),
            $pipes,
            null,
            array()
        );

        // give readable names to the pipes
        $this->stdin = $pipes[0];
        $this->stdout = $pipes[1];
        $this->stderr = $pipes[2];

        // process failed to start?
        if ($this->process === false) return false;

        // process started successfully

        /*
         * set the streams to non-blocking mode, so we don't end up in a
         * never-ending function call when reading, such as when no data is
         * available and the end of stream hasn't been reached
         */ 
        if (stream_set_blocking($this->stdin, 0) === false) return;
        if (stream_set_blocking($this->stdout, 0) === false) return;
        if (stream_set_blocking($this->stderr, 0) === false) return;

        // assume we're at password prompt

        if ($this->_write($this->stdin, 1500, "{$password}\n") === false) {
            // relaying of password to kinit failed
            return false;
        }
        // password given to 'kinit'

        // read stdout and stderr
        $ret = $this->_readUntilExit($this->stdout, $this->stderr, 3000);
        if ($ret === false) return false;

        // check return values

        /*
         * password successfully verified:
         * (stderr): kinit(v5): Credentials cache file permissions incorrect
         *           when initializing cache /dev/null
         * (stderr): [empty result], exitCode == 0
         */

        if (stripos($ret[1], 'Credentials cache file permissions incorrect when initializing cache /dev/null') !== false) {
            // error was that permissions failed. relying on kinit's implementation that this message is received only when password check has passed
            return true;
        } else if ($ret[1] === '') {
            // no error message. ensuring that kinit's exit code is also zero to indicate success
            if ($this->exitcode === 0) return true;
        }

        // kinit returned something that doesn't qualify as verified credentials
        return false;
    }

    /**
     * Write data to stream or timeout.
     * 
     * @param resource $stream - Stream to write to
     * @param int $timeout - Timeout in milliseconds.
     * @param string $data - Data to be written.
     * @return bool - True if successful, false otherwise (and on timeout).
     */
    private function _write($stream, $timeout, $data) {
        if (!is_resource($stream)) return false;

        // save time when to timeout
        $timeout = microtime(true) + ($timeout * 1000);
        $aEmpty = array();

        $totalWritten = 0;

        // loop until everything's written
        while ($totalWritten < strlen($data)) {
            if (microtime(true) >= $timeout) return false;

            // wait until stream is ready for writing
            $writeArray = array($stream);
            $changes = stream_select($aEmpty, $writeArray, $aEmpty, 0, 50000 /* 50ms */);
            // failed. cancel
            if ($changes === false) return false;
            // no streams changed (timeout). retry
            if ($changes === 0) continue;

            // write
            $written = fwrite($stream, substr($data, $totalWritten));
            if ($written === false) return false;
            $totalWritten += $written;
        }

        // data successfully written
        return true;
    }

    /**
     * Read data from two streams seperately until 'kinit' has died or timeout
     * exceeded.
     * 
     * @param resource $stream1 - Stream 1 to read data from
     * @param resource $stream2 - Stream 2 to read data from
     * @param int $timeout - Timeout in milliseconds.
     * @return mixed - Failure and timeout: false, on success:
     *                 array ([0] = data from stream 1, [1] = data from stream 2).
     */

    private function _readUntilExit($stream1, $stream2, $timeout) {
        if (!is_resource($stream1)) return false;
        if (!is_resource($stream2)) return false;

        // save time when to timeout
        $timeout = microtime(true) + ($timeout * 1000);
        $aEmpty = array();

        $stream1Read = '';
        $stream2Read = '';

        // loop forever
        while (true) {
            if (microtime(true) >= $timeout) return false;

            // wait until any of the streams is ready for reading
            $readArray = array($stream1, $stream2);
            $changes = stream_select($readArray, $aEmpty, $aEmpty, 0, 50000 /* 50ms */);

            if ($changes !== false) {
                // how many streams changed
                switch ($changes) {
                    default: // fall-back, in case something unexpected happens :I
                    case 0:
                        // no streams changed (timeout)
                        $readWhat = 0;
                        break;
                    case 1:
                        // one stream is ready
                        if ($readArray[0] === $stream1) $readWhat = 1;
                        else $readWhat = 2;
                        break;
                    case 2:
                        // both streams are ready
                        $readWhat = 3;
                        break;
                }

                // read from the streams and append read data to stream specific variables

                if (@$readWhat === 1 || @$readWhat === 3) {
                    // execute this block of code if order was to read stream 1 or both
                    $read = fread($stream1, 8192);
                    if ($read !== false) $stream1Read .= $read;
                }

                if (@$readWhat === 2 || @$readWhat === 3) {
                    // execute this block of code if order was to read stream 2 or both
                    $read = fread($stream2, 8192);
                    if ($read !== false) $stream2Read .= $read;
                }

            } // changes !== false

            // check if process has died
            $status = proc_get_status($this->process);
            if ($status === false) return false;
            if ($status['running'] === false) {
                // successfully died, save exit code
                $this->exitcode = $status['exitcode'];
                break;
            }
        }

        // return data read from the streams
        return array($stream1Read, $stream2Read);
    }

    /**
     * Cleans up 'kinit' process.
     */
    private function _cleanup() {
        @fclose($this->stdin);
        @fclose($this->stdout);
        @fclose($this->stderr);
        @proc_terminate($this->process, 15); // 15 = SIGTERM / request shutdown
        usleep(300 * 1000); // 300ms
        @proc_terminate($this->process, 9); // 9 = SIGKILL / terminate
        @proc_close($this->process);
    }

}
