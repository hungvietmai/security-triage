import { Link } from "@tanstack/react-router";
import { PageHeader } from "@/components/common/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { paths } from "@/config/paths";

export function ScansRoute() {
  return (
    <>
      <PageHeader
        title="Lượt quét"
        description="Theo dõi các lượt chạy Semgrep và CodeQL trên từng bản mã nguồn."
      />
      <Card>
        <CardHeader>
          <CardTitle>Tạo scan từ dự án</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm text-muted-foreground">
            Chọn dự án để quét phiên bản npm hoặc commit GitHub. Mỗi scan có
            trang trạng thái và bằng chứng riêng; API chưa hỗ trợ danh sách tất
            cả scan.
          </p>
          <Button asChild>
            <Link to={paths.projects.path} search={{ page: 1 }}>
              Chọn dự án
            </Link>
          </Button>
        </CardContent>
      </Card>
    </>
  );
}
