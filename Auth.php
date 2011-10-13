<?php
/** [LGPL] Copyright 2011 Gima

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
 * Authenticate against Itä-Suomen Yliopisto UEFAD Active Directory
 * on cs.joensuu.fi by using local Kerberos 'kinit' executable. 
 * 
 * @author Gima
 */
class Auth {
	
	/*
	* Quirky behavior
	* ---------------
	* 
	* Because 'kinit' insists on writing the ticket to a file with PHP process's permissions,
	* it would be bad on servers whose PHP executes under fixed user and group.
	*
	* Instead we force 'kinit' to write to a file that it doesn't have access to (or /dev/null)
	* and record the error message. If the error message tells us that 'kinit' failed to write the
	* ticket file because of permission errors or something similar, it's a valid authentication *gasp*
	* OR If no error message was outputted, everything went better than expected.
	*/
	
	/** PHP process handler; to share easily between functions */
	private $process;
	/** 'kinit's stdin stream */
	private $stdin;
	/** 'kinit's stdout stream */
	private $stdout;
	/** 'kinit's stderr stream */
	private $stderr;
	/** Enforces staying in this script for long enough (chat with cs.joensuu.fi admin) */
	private $fixedSleepSecs = 5;

	/**
	 * Authenticate against Itä-Suomen Yliopisto UEFAD Active Directory with the given username and password,
	 * saves the fact to a session.
	 * 
	 * This function has to wait at least ${fixedSleepSecs} seconds (chat with 'cs.joensuu.fi' administrator),
	 * unless the user is already logged in.
	 * 
	 * @param string $username - Username for login.
	 * @param string $password - Password for login.
	 * @return boolean - True for successful login, false otherwise.
	 * @author Gima
	 */
	public function login($username, $password) {
		if ($this->isLoggedIn()) return true;
		if (!$this->isUsernameOk($username)) return false;
		
		$loginStartTime = microtime(true);
		
		$bSuccess = $this->_login($username, $password);
		if ($bSuccess) {
			$_SESSION['UEFAD_USERNAME'] = $username;
		}
		
		$this->delayExecution($loginStartTime);
		
		return $bSuccess;
	}
	
	/**
	 * Unsets possible session login state.
	 * 
	 * @author Gima
	 */
	public function logout() {
		unset($_SESSION['UEFAD_USERNAME']);
	}
	
	/**
	 * Returns whether logged in or not.
	 *  
	 * @return boolean - True if logged in, false otherwise
	 * @author Gima
	 */
	public function isLoggedIn() {
		return isset($_SESSION['UEFAD_USERNAME']);
	}
	
	/**
	 * Retrieves the logged in username.
	 * 
	 * @return string - Username, or null if not logged.
	 * @author Gima
	 */
	public function getUsername() {
		if (!isset($_SESSION['UEFAD_USERNAME'])) return null;
		else return $_SESSION['UEFAD_USERNAME'];
	}
	
	/**
	 * Perform the actual login to UEFAD on cs.joensuu.fi with 'kinit'.
	 * 
	 * @param string $username - The username used to log in.
	 * @param string $password - The password used to log in.
	 * @return boolean - True if login was successful, false otherwise
	 * @author Gima
	 */
	private function _login($username, $password) {
		
		/*
		 * "-l 1s"
		 *  Meaning: request ticket valid time of 1 second
		 * "-c /dev/null"
		 *  Meaning: Write ticket file to /dev/null
		 */
		$cmd = "kinit -l 1s -c /dev/null {$username}";
		
		/*
		 * start 'kinit' process and direct it's stdin, stdout and stderr to php's side
		 * for reading writing
		 */
		$pipes = array();
		$this->process = proc_open(
			$cmd,
			array(
				0 => array('pipe', 'r'),
				1 => array('pipe', 'w'),
				2 => array('pipe', 'w'),
			),
			$pipes,
			null,
			array()
		);
		
		// give readable names to the pipes
		$this->stdin = $pipes[0];
		$this->stdout = $pipes[1];
		$this->stderr = $pipes[2];
		
		if ($this->process === false) {
			$this->processCleanup();
			return false;
		}
		
		// process started successfully
		
		/*
		 * set the stream to asynchronous, non-blocking mode, so we don't end up in a neverending
		 * function call when reading-- when o data may be available but no end of stream has been reached either
		 */ 
		stream_set_blocking($this->stdin, 0);
		stream_set_blocking($this->stdout, 0);
		stream_set_blocking($this->stderr, 0);
		
		// try to determine if at password prompt
		$readStdOut = $this->read($this->stdout, 1.5, function($testString) {
			if (strpos($testString, 'Password for ') === false) return false;
			return true;
		});
		
		if ($readStdOut === false) {
			/*
			 * something else than password request was read. maybe updated kinit?
			 * OR read failed = error
			 */
			$this->processCleanup();
			return false;
		}
		
		// password prompt read successfully
		
		if ($this->write($this->stdin, 1.5, "{$password}\n") === false) {
			// relaying of password to kinit failed
			$this->processCleanup();
			return false;
		}
		
		// password given successfully to 'kinit'
		
		// read stderr
		$readStdErr = $this->read($this->stderr, 3, function($testString) {
			return false;
		});
		
		if ($readStdErr === false) {
			// failed to read stderr = error
			$this->processCleanup();
			return false;
		}
		
		/*
		 * something was read from stderr, or EOF
		 * determine what it was
		 */

		if (strpos($readStdErr, 'Credentials cache file permissions incorrect') !== false) {
			/*
			 * password check passed, no permission to write ticket file.
			 * we don't case about the ticket, we just need to know if the authentication succeeded
			 */
			$this->processCleanup();
			return true;
		}
		else if (strpos($readStdErr, 'No credentials cache file found') !== false) {
			/*
			 * password check passed, but (presumably) the directory to write the ticket to didn't exist.
			 * we don't case about the ticket, we just need to know if the authentication succeeded
			 */
			$this->processCleanup();
			return true;
		}
		else {
			if ($this->processCleanup() === 0) {
				// password check passed and ticket was written to /dev/null. Huzzah!
				return true;
			}
			else {
				// something went wrong
				return false;
			}
		}
	}
	
	/**
	 * Stream read function with timeout and continuation test function callback. Writes
	 * 
	 * @param resource $handle - Stream to read from
	 * @param int $timeoutInSecs - Timeout in seconds. If passed, returns currently read string.
	 * @param callback $stringTestFunc - Function gets one parameter (string read so far) and must return
	 * either true to indicate stop reading or false to indicate continue reading.
	 * @return string - String read from stream (can be '') and false on failure
	 * @author Gima 
	 */
	private function read($handle, $timeoutInSecs, $stringTestFunc) {
		if (!is_resource($handle)) return false;
		if (feof($handle)) return '';
		
		$timeout = microtime(true) + $timeoutInSecs;
		$totalRead = '';
		$writeArray = array();
		$exceptArray = array();
		
		while (true) {
			if (feof($handle)) return $totalRead;
			
			$readArray = array($handle);
			if (stream_select($readArray, $writeArray, $exceptArray, 0, 25000) === false) return false;
			if (microtime(true) >= $timeout) break;
			if (count($readArray) === 0) continue;
			
			$read = fread($handle, 8192);
			if ($read === false) return false;
			
			$totalRead .= $read;
			if ($stringTestFunc($totalRead) === true) break;
		}
		
		return $totalRead;
	}
	
	/**
	 * Stream write function that makes sure the data requested to be written is really written optionally with timeout.
	 * 
	 * @param resource $handle - Stream to write to
	 * @param int $timeoutInSecs - Timeout in seconds. Will return false if passed.
	 * @param string $data - Data to be written.
	 * @return bool - True if successful, false otherwise.
	 * @author Gima
	 */
	private function write($handle, $timeoutInSecs, $data) {
		if (!is_resource($handle)) return false;
		
		$timeout = microtime(true) + $timeoutInSecs;
		$totalWritten = 0;
		$readArray = array();
		$exceptArray = array();
		
		while ($totalWritten < strlen($data)) {
			$writeArray = array($handle);
			if (stream_select($readArray, $writeArray, $exceptArray, 0, 25000) === false) return false;
			if (microtime(true) >= $timeout) return false;
			if (count($writeArray) === 0) continue;
			
			$written = fwrite($handle, substr($data, $totalWritten));
			if ($written === false) return false;
			$totalWritten += $written;
		}
		
		return true;
	}
	
	/**
	 * Makes sure the 'kinit' process closes neatly.
	 * 
	 * @author Gima
	 */
	private function processCleanup() {
		@fclose($this->stdin);
		@fclose($this->stdout);
		@fclose($this->stderr);
		$ret = @proc_close($this->process);
		@proc_terminate($this->process, 9);
		
		return $ret;
	}
	
	/**
	 * Delays the execution of the script for at least $fixedSleepSecs amount, calculated from the given parameter.
	 * 
	 * @param float $loginStartTime - Time from where to start counting. Format is the same that
	 * microtime(true) returns.
	 * @author Gima
	 */
	private function delayExecution($loginStartTime) {
		$acceptableLoss = 0.5; // 0.5sec
		$diff = microtime(true) - $loginStartTime;
		if ($this->fixedSleepSecs - $diff >= $acceptableLoss) {
			$sleepTime = round(($this->fixedSleepSecs - $diff) * 1000000);
			//echo 'usleep:' . $sleepTime;
			usleep($sleepTime);
		}
	}
	
	/**
	 * Ensures the username given to this function contains only alpanumeric characters and any of the following
	 * "+-_.," and is not empty
	 * 
	 * @param string $username - The username to test for validness.
	 * @return bool - True if the username is passes the tests, false otherwise.
	 * @author Gima
	 */
	private function isUsernameOk($username) {
		if (strlen($username) === 0) return false;
		return preg_match('/^[a-z0-9+-_.,]*$/i', $username);
	}
	
}

$auth = new Auth();
?>
