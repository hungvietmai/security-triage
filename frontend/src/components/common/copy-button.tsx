import { CheckIcon, CopyIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";

export function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) return;
    const timer = setTimeout(() => setCopied(false), 1500);
    return () => clearTimeout(timer);
  }, [copied]);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
    } catch {
      toast.error("Trình duyệt không cho phép sao chép.");
    }
  }

  return (
    <Button
      variant="ghost"
      size="icon-xs"
      onClick={copy}
      aria-label={copied ? "Đã sao chép" : label}
      title={label}
    >
      {copied ? <CheckIcon /> : <CopyIcon />}
    </Button>
  );
}
