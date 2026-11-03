"use client";

import { z } from "zod";

import { AuthForm } from "@/components/auth/auth-form";
import { api, unwrap } from "@/lib/api";

// Mirrors the API rules (the API remains authoritative).
const name = (min: number, max: number) =>
  z
    .string()
    .trim()
    .min(min, `At least ${min} characters`)
    .max(max)
    .regex(/^[^\p{Cc}\p{Cf}]+$/u, "Control characters are not allowed");

const schema = z
  .object({
    display_name: name(1, 100),
    organization_name: name(2, 120),
    email: z.email("Enter a valid email"),
    password: z.string().min(12, "At least 12 characters").max(128),
  })
  .refine((v) => v.password.trim().toLowerCase() !== v.email.toLowerCase(), {
    path: ["password"],
    message: "Password must not equal your email",
  });

export default function RegisterPage() {
  return (
    <AuthForm
      title="Create your workspace"
      description="You become the owner of a new organization."
      schema={schema}
      fields={[
        { name: "display_name", label: "Your name", autoComplete: "name" },
        { name: "organization_name", label: "Organization", autoComplete: "organization" },
        { name: "email", label: "Email", type: "email", autoComplete: "email" },
        { name: "password", label: "Password", type: "password", autoComplete: "new-password" },
      ]}
      submitLabel="Create account"
      submit={async (body) => unwrap(await api.POST("/api/v1/auth/register", { body }))}
      footer={{ text: "Already have an account?", href: "/login", link: "Sign in" }}
    />
  );
}
