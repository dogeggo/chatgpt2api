"use client";

import { useEffect, useMemo, useState } from "react";
import {
  CheckCircle2,
  CircleAlert,
  KeyRound,
  LoaderCircle,
  LogIn,
  MailCheck,
  RotateCcw,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  fetchBatchLoginJob,
  fetchRegisterConfig,
  startBatchLogin,
  type BatchLoginCloudflareTempEmail,
  type BatchLoginItem,
  type BatchLoginJob,
  type RegisterConfig,
} from "@/lib/api";
import { useAuthGuard } from "@/lib/use-auth-guard";
import { cn } from "@/lib/utils";

function parseEmails(value: string) {
  const seen = new Set<string>();
  const emails: string[] = [];
  value.split(/\r?\n/).forEach((line) => {
    const email = line.trim();
    if (!email) return;
    const key = email.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    emails.push(email);
  });
  return emails;
}

function resultVariant(item: BatchLoginItem) {
  return item.status === "成功"
    ? "success"
    : item.status === "失败"
      ? "danger"
      : "secondary";
}

function formatTime(value?: string) {
  if (!value) return "--";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value.slice(0, 19);
  return date.toLocaleTimeString("zh-CN", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function findCloudflareTempEmailProvider(config: RegisterConfig) {
  const providers = Array.isArray(config.mail?.providers)
    ? config.mail.providers
    : [];
  return (
    providers.find(
      (provider) =>
        Boolean(provider.enable) &&
        String(provider.type || "") === "cloudflare_temp_email",
    ) ??
    providers.find(
      (provider) => String(provider.type || "") === "cloudflare_temp_email",
    )
  );
}

function BatchLoginPageContent() {
  const [emailText, setEmailText] = useState("");
  const [apiBase, setApiBase] = useState("");
  const [adminPassword, setAdminPassword] = useState("");
  const [customPassword, setCustomPassword] = useState("");
  const [proxy, setProxy] = useState("");
  const [job, setJob] = useState<BatchLoginJob | null>(null);
  const [activeJobId, setActiveJobId] = useState("");
  const [isStarting, setIsStarting] = useState(false);
  const emails = useMemo(() => parseEmails(emailText), [emailText]);
  const isRunning = Boolean(activeJobId && job && !job.done);
  const progress =
    job && job.total > 0 ? Math.round((job.processed * 100) / job.total) : 0;

  useEffect(() => {
    let closed = false;
    const loadMailConfig = async () => {
      try {
        const data = await fetchRegisterConfig();
        if (closed) return;
        const savedProxy = String(data.register.proxy || "");
        setProxy((current) => current || savedProxy);
        const provider = findCloudflareTempEmailProvider(data.register);
        if (!provider) return;
        const savedApiBase = String(provider.api_base || "");
        const savedAdminPassword = String(provider.admin_password || "");
        const savedCustomPassword = String(provider.custom_password || "");
        setApiBase((current) => current || savedApiBase);
        setAdminPassword((current) => current || savedAdminPassword);
        setCustomPassword((current) => current || savedCustomPassword);
      } catch (error) {
        if (!closed) {
          toast.error(
            error instanceof Error ? error.message : "加载邮箱服务配置失败",
          );
        }
      }
    };

    void loadMailConfig();
    return () => {
      closed = true;
    };
  }, []);

  useEffect(() => {
    if (!activeJobId) return;
    let closed = false;
    let timer: ReturnType<typeof setInterval> | null = null;

    const load = async () => {
      try {
        const data = await fetchBatchLoginJob(activeJobId);
        if (closed) return;
        setJob(data.job);
        if (data.job.done) {
          setActiveJobId("");
          if (data.job.error) {
            toast.error(data.job.error);
          } else {
            toast.success(
              `批量登录完成：成功 ${data.job.success}，失败 ${data.job.fail}`,
            );
          }
        }
      } catch (error) {
        if (closed) return;
        setActiveJobId("");
        toast.error(
          error instanceof Error ? error.message : "获取批量登录进度失败",
        );
      }
    };

    void load();
    timer = setInterval(() => void load(), 1000);
    return () => {
      closed = true;
      if (timer) clearInterval(timer);
    };
  }, [activeJobId]);

  const handleStart = async () => {
    if (emails.length === 0) {
      toast.error("邮箱列表不能为空");
      return;
    }
    const cloudflareTempEmail: BatchLoginCloudflareTempEmail = {
      api_base: apiBase.trim(),
      admin_password: adminPassword.trim(),
      custom_password: customPassword.trim(),
    };
    const hasMailConfig = Boolean(
      cloudflareTempEmail.api_base ||
      cloudflareTempEmail.admin_password ||
      cloudflareTempEmail.custom_password,
    );
    if (
      hasMailConfig &&
      (!cloudflareTempEmail.api_base || !cloudflareTempEmail.admin_password)
    ) {
      toast.error("API Base 和 Admin Password 不能为空");
      return;
    }
    setIsStarting(true);
    try {
      const data = await startBatchLogin(
        emails,
        {
          ...(hasMailConfig ? { cloudflareTempEmail } : {}),
          proxy: proxy.trim(),
        },
      );
      setJob(data.job);
      setActiveJobId(data.job.job_id);
      toast.success(`已提交 ${data.job.total} 个邮箱`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "批量登录启动失败");
    } finally {
      setIsStarting(false);
    }
  };

  return (
    <>
      <section className="mb-3 flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
        <div className="space-y-1">
          <div className="text-xs font-semibold tracking-[0.18em] text-stone-500 uppercase">
            Batch Login
          </div>
          <h1 className="text-2xl font-semibold tracking-tight">批量登录</h1>
        </div>
        <Badge
          variant="outline"
          className="w-fit rounded-md border-stone-200 bg-white text-stone-600"
        >
          cloudflare_temp_email
        </Badge>
      </section>

      <div className="grid h-[calc(100vh-132px)] min-h-[620px] overflow-hidden rounded-xl border border-stone-200 bg-white/70 lg:grid-cols-[minmax(320px,420px)_1fr]">
        <section className="flex min-h-0 flex-col gap-4 border-b border-stone-200 p-4 lg:border-r lg:border-b-0">
          <div className="flex items-center gap-3">
            <div className="flex size-9 items-center justify-center rounded-md bg-stone-100">
              <MailCheck className="size-5 text-stone-600" />
            </div>
            <div>
              <h2 className="text-lg font-semibold tracking-tight">邮箱列表</h2>
              <div className="mt-0.5 text-xs text-stone-500">
                已识别 {emails.length} 个
              </div>
            </div>
          </div>

          <div className="space-y-3 border-t border-stone-200 pt-3">
            <div className="flex items-center gap-3">
              <div className="flex size-9 items-center justify-center rounded-md bg-stone-100">
                <KeyRound className="size-5 text-stone-600" />
              </div>
              <div>
                <h2 className="text-lg font-semibold tracking-tight">
                  邮箱服务
                </h2>
              </div>
            </div>
            <div className="grid gap-3">
              <div className="space-y-2">
                <label className="text-sm text-stone-700">登录代理</label>
                <Input
                  value={proxy}
                  onChange={(event) => setProxy(event.target.value)}
                  placeholder="http://127.0.0.1:7890"
                  className="h-10 rounded-xl border-stone-200 bg-white"
                  disabled={isRunning || isStarting}
                />
              </div>
              <div className="space-y-2">
                <label className="text-sm text-stone-700">API Base</label>
                <Input
                  value={apiBase}
                  onChange={(event) => setApiBase(event.target.value)}
                  placeholder="https://worker.example.com"
                  className="h-10 rounded-xl border-stone-200 bg-white font-mono text-xs"
                  disabled={isRunning || isStarting}
                />
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-2">
                  <label className="text-sm text-stone-700">
                    Admin Password
                  </label>
                  <Input
                    type="text"
                    value={adminPassword}
                    onChange={(event) => setAdminPassword(event.target.value)}
                    className="h-10 rounded-xl border-stone-200 bg-white font-mono text-xs"
                    disabled={isRunning || isStarting}
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm text-stone-700">
                    Custom Password
                  </label>
                  <Input
                    type="text"
                    value={customPassword}
                    onChange={(event) => setCustomPassword(event.target.value)}
                    className="h-10 rounded-xl border-stone-200 bg-white font-mono text-xs"
                    disabled={isRunning || isStarting}
                  />
                </div>
              </div>
            </div>
          </div>

          <Textarea
            value={emailText}
            onChange={(event) => setEmailText(event.target.value)}
            placeholder={"user01@example.com\nuser02@example.com"}
            className="min-h-40 flex-1 resize-none rounded-xl border-stone-200 bg-white font-mono text-xs leading-6 shadow-none"
            disabled={isRunning || isStarting}
          />

          <div className="grid grid-cols-3 gap-2">
            <div className="border border-stone-200 bg-white/80 px-3 py-2">
              <div className="text-xs text-stone-400">总数</div>
              <div className="mt-1 text-lg font-semibold text-stone-900">
                {job?.total ?? emails.length}
              </div>
            </div>
            <div className="border border-stone-200 bg-white/80 px-3 py-2">
              <div className="text-xs text-stone-400">成功</div>
              <div className="mt-1 text-lg font-semibold text-emerald-600">
                {job?.success ?? 0}
              </div>
            </div>
            <div className="border border-stone-200 bg-white/80 px-3 py-2">
              <div className="text-xs text-stone-400">失败</div>
              <div className="mt-1 text-lg font-semibold text-rose-500">
                {job?.fail ?? 0}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <Button
              className="h-10 rounded-xl bg-stone-950 px-3 text-white hover:bg-stone-800"
              onClick={() => void handleStart()}
              disabled={emails.length === 0 || isRunning || isStarting}
            >
              {isStarting || isRunning ? (
                <LoaderCircle className="size-4 animate-spin" />
              ) : (
                <LogIn className="size-4" />
              )}
              开始登录
            </Button>
            <Button
              variant="outline"
              className="h-10 rounded-xl border-stone-200 bg-white px-3 text-stone-700"
              onClick={() => {
                setEmailText("");
                setJob(null);
              }}
              disabled={isRunning || isStarting}
            >
              <RotateCcw className="size-4" />
              清空
            </Button>
          </div>
        </section>

        <section className="flex min-h-0 flex-col p-4">
          <div className="space-y-3">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <h2 className="text-lg font-semibold tracking-tight">
                  任务状态
                </h2>
                <div className="mt-1 text-sm text-stone-500">
                  {job?.current_email
                    ? `${job.current_email} · ${job.current_step || "处理中"}`
                    : job
                      ? "任务已完成或等待提交"
                      : "等待提交"}
                </div>
              </div>
              <Badge
                variant={
                  isRunning ? "warning" : job?.done ? "success" : "secondary"
                }
                className="w-fit rounded-md"
              >
                {isRunning ? "运行中" : job?.done ? "已完成" : "未开始"}
              </Badge>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-stone-100">
              <div
                className="h-full bg-stone-950 transition-all"
                style={{ width: `${progress}%` }}
              />
            </div>
            <div className="flex items-center justify-between text-xs text-stone-500">
              <span>{job ? `${job.processed}/${job.total}` : "0/0"}</span>
              <span>{progress}%</span>
            </div>
          </div>

          <div className="mt-4 min-h-0 flex-1 overflow-hidden border-t border-stone-200 pt-4">
            <div className="grid h-full min-h-0 gap-4 xl:grid-cols-[1fr_320px]">
              <div className="min-h-0 overflow-auto border border-stone-200 bg-white/80">
                <table className="w-full min-w-[720px] text-left">
                  <thead className="border-b border-stone-100 text-[11px] tracking-[0.18em] text-stone-400 uppercase">
                    <tr>
                      <th className="w-64 px-4 py-3">邮箱</th>
                      <th className="w-24 px-4 py-3">状态</th>
                      <th className="w-36 px-4 py-3">token</th>
                      <th className="px-4 py-3">结果</th>
                      <th className="w-24 px-4 py-3">时间</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-stone-100 text-sm">
                    {(job?.items || []).length === 0 ? (
                      <tr>
                        <td
                          colSpan={5}
                          className="px-4 py-12 text-center text-sm text-stone-500"
                        >
                          暂无结果
                        </td>
                      </tr>
                    ) : (
                      job?.items.map((item) => (
                        <tr
                          key={`${item.email}-${item.finished_at || item.status}`}
                        >
                          <td className="break-all px-4 py-3 font-mono text-xs text-stone-700">
                            {item.email}
                          </td>
                          <td className="px-4 py-3">
                            <Badge
                              variant={resultVariant(item)}
                              className="rounded-md"
                            >
                              {item.status === "成功" ? (
                                <CheckCircle2 className="mr-1 size-3" />
                              ) : item.status === "失败" ? (
                                <CircleAlert className="mr-1 size-3" />
                              ) : null}
                              {item.status}
                            </Badge>
                          </td>
                          <td className="break-all px-4 py-3 font-mono text-xs text-stone-500">
                            {item.token || "--"}
                          </td>
                          <td
                            className={cn(
                              "break-words px-4 py-3 text-xs",
                              item.status === "失败"
                                ? "text-rose-600"
                                : "text-stone-500",
                            )}
                          >
                            {item.error || item.message || "--"}
                          </td>
                          <td className="px-4 py-3 text-xs text-stone-500">
                            {formatTime(item.finished_at)}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>

              <div className="min-h-0 overflow-y-auto border border-stone-200 bg-white/80 p-3 font-mono text-xs leading-6">
                {(job?.logs || []).length === 0 ? (
                  <div className="text-stone-500">暂无日志</div>
                ) : (
                  job?.logs
                    .slice()
                    .reverse()
                    .map((item, index) => (
                      <div
                        key={`${item.time}-${item.email}-${index}`}
                        className={
                          item.level === "red"
                            ? "text-rose-600"
                            : item.level === "green"
                              ? "text-emerald-700"
                              : "text-stone-700"
                        }
                      >
                        <span className="text-stone-400">
                          {formatTime(item.time)}
                        </span>
                        <span className="pl-2">{item.email}</span>
                        <span className="pl-2">{item.text}</span>
                      </div>
                    ))
                )}
              </div>
            </div>
          </div>
        </section>
      </div>
    </>
  );
}

export default function BatchLoginPage() {
  const { isCheckingAuth, session } = useAuthGuard(["admin"]);

  if (isCheckingAuth || !session || session.role !== "admin") {
    return (
      <div className="flex min-h-[40vh] items-center justify-center">
        <LoaderCircle className="size-5 animate-spin text-stone-400" />
      </div>
    );
  }

  return <BatchLoginPageContent />;
}
