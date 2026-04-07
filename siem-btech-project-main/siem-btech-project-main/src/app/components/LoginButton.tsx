"use client";

import { auth } from "@/lib/firebase";
import { GoogleAuthProvider, signInWithPopup, signOut } from "firebase/auth";
import { useAuth } from "./AuthProvider";

export default function LoginButton() {
  const { user, loading } = useAuth();

  async function login() {
    const provider = new GoogleAuthProvider();
    await signInWithPopup(auth, provider);
  }

  async function logout() {
    await signOut(auth);
  }

  if (loading) {
    return (
      <div className="text-xs text-gray-600 dark:text-zinc-400">
        Loading…
      </div>
    );
  }

  return user ? (
    <div className="flex items-center gap-2">
      <span className="text-xs text-gray-700 dark:text-zinc-300">
        {user.displayName ?? user.email}
      </span>
      <button
        onClick={logout}
        className="rounded-xl border px-3 py-2 text-xs font-semibold
                   hover:bg-gray-50 dark:border-zinc-700 dark:text-white dark:hover:bg-zinc-800"
      >
        Logout
      </button>
    </div>
  ) : (
    <button
      onClick={login}
      className="rounded-xl bg-black px-3 py-2 text-xs font-semibold text-white
                 dark:bg-white dark:text-black"
    >
      Sign in with Google
    </button>
  );
}