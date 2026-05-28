import React, { createContext, useCallback, useContext, useMemo, useState } from "react";

interface AuthState {
  token: string | null;
  setToken: (token: string | null) => void;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthState>({
  token: null,
  setToken: () => undefined,
  isAuthenticated: false,
});

export function AuthProvider({ children }: { children: React.ReactNode }): React.ReactElement {
  const [token, setTokenState] = useState<string | null>(
    () => localStorage.getItem("hitl_token"),
  );

  const setToken = useCallback((t: string | null) => {
    setTokenState(t);
    if (t) {
      localStorage.setItem("hitl_token", t);
    } else {
      localStorage.removeItem("hitl_token");
    }
  }, []);

  const value = useMemo<AuthState>(
    () => ({ token, setToken, isAuthenticated: token !== null }),
    [token, setToken],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  return useContext(AuthContext);
}
