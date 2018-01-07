# geoprobe
geoprobe is a tool to sniff, collect and geolocate 802.11 ProbeRequests using WiGLE API.

The code is very raw as I had little time to put it together but it does what it needs to do.
Dependencies, also listed in the install file, are the following python3 modules:
* pyric
* scapy
* geohash_hilbert
* pygle

Some configuration and a WiGLE account are also needed to use the app's location capabilities.

This is a command line version proof-of-concept of what Zahori (a GUI application that does a better job than this tool does) should do that I'll actually managed to kind of finish before the deadline. Also, GitHub recommends didactit-fortnight as a name for this repository, I think you should know.

## Similar software
* [ProbeKit by brannondorsey](https://github.com/brannondorsey/ProbeKit) is a more sofisticated data collection tool that allows you to gather and visualize this kind of info.

## Disclaimer
This tool is provided for educational purposes only. The author of this tool is not responsible for any misuse. You shall not misuse the tool to gain unauthorized access to otherwise private information. The tool shall only be used to expand knowledge in IT security and never for causing malicious or damaging attacks to any individuals or groups. Use at your own risk.

IN NO EVENT SHALL THE CREATORS, OWNER, OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
