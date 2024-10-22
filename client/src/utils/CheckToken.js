import { jwtDecode } from "jwt-decode";
import Cookie from "js-cookie";

function checkToken() {
  const jwtToken = Cookie.get("jwtToken");
  if (jwtToken) {
    const decodedToken = jwtDecode(jwtToken);
    const currentTime = Date.now() / 1000;
    if (decodedToken.exp < currentTime) {
      //   window.localStorage.removeItem("jwtToken");
      Cookie.remove("jwtToken");
      return false;
    } else {
      return true;
    }
  }
}

export default checkToken;
