import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { me } from "../api/auth.api";
import { Loader } from "../components/common";
import { useAuth } from "../stores/auth";

/** Landing page after the identity provider redirects back. The session is already an httpOnly cookie; this just
 *  asks the server who we are and enters the app. */
export default function SsoComplete() {
  const nav = useNavigate();
  const setSession = useAuth((s) => s.setSession);
  useEffect(() => {
    me()
      .then((u) => { setSession("cookie-session", u); nav(u.must_change_password ? "/change-password" : "/dashboard", { replace: true }); })
      .catch(() => nav("/login?sso_error=1", { replace: true }));
  }, [nav, setSession]);
  return <div className="p-10"><Loader /></div>;
}
