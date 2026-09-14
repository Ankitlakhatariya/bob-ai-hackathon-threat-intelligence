import { Link } from 'react-router-dom'
import { Construction } from 'lucide-react'

export function PageStub({ title }: { title: string }) {
  return (
    <section className="flex flex-col items-center justify-center gap-4 rounded-xl border border-dashed border-border py-24 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-accent/15 text-accent">
        <Construction className="h-6 w-6" aria-hidden="true" />
      </div>
      <h1 className="text-2xl font-bold">{title}</h1>
      <p className="max-w-md text-sm leading-relaxed text-foreground-muted">
        This module is the next build step. Navigation stays wired so links never break while pages
        are under construction.
      </p>
      <Link
        to="/dashboard"
        className="mt-2 inline-flex items-center justify-center rounded-lg bg-primary px-5 py-2.5 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90"
      >
        Back to dashboard
      </Link>
    </section>
  )
}