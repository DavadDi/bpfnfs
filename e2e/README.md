# 构建镜像
docker build -t ghostbaby/nfs-e2e:lateset .

# 镜像导出
docker save ghostbaby/nfs-e2e:lateset -o nfs-e2e.tar

# containerd 镜像导出
ctr -n k8s.io image export ghostbaby/nfs-e2e:lateset nfs-e2e.tar

# 部署
kubectl apply -f ./deploy/manifest.yaml