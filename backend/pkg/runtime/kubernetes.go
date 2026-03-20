package runtime

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	clientset *kubernetes.Clientset
	once      sync.Once

	containerMap map[string]metav1.ObjectMeta

	cacheMutex  sync.RWMutex
	cacheExpiry time.Time

	cacheDuration = 5 * time.Second
)

/*
Initialize Kubernetes client only once
*/
func getClient() *kubernetes.Clientset {

	once.Do(func() {

		kubeconfig := os.Getenv("KUBECONFIG")

		if kubeconfig == "" {

			home, err := os.UserHomeDir()
			if err != nil {
				log.Println("runtime: failed to resolve home directory:", err)
				return
			}

			kubeconfig = filepath.Join(home, ".kube", "config")
		}

		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			log.Println("runtime: kubeconfig load error:", err)
			return
		}

		cs, err := kubernetes.NewForConfig(config)
		if err != nil {
			log.Println("runtime: kubernetes client error:", err)
			return
		}

		clientset = cs
		containerMap = make(map[string]metav1.ObjectMeta)

		log.Println("runtime: kubernetes client initialized")
	})

	return clientset
}

/*
Refresh pod cache

containerID -> pod metadata
*/
func refreshCache(cs *kubernetes.Clientset) {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pods, err := cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Println("runtime: pod list error:", err)
		return
	}

	newMap := make(map[string]metav1.ObjectMeta)

	for _, pod := range pods.Items {

		meta := pod.ObjectMeta

		processContainer := func(containerID string) {

			id := normalizeContainerID(containerID)

			if id == "" {
				return
			}

			newMap[id] = meta
		}

		for _, c := range pod.Status.ContainerStatuses {
			processContainer(c.ContainerID)
		}

		for _, c := range pod.Status.InitContainerStatuses {
			processContainer(c.ContainerID)
		}

		for _, c := range pod.Status.EphemeralContainerStatuses {
			processContainer(c.ContainerID)
		}
	}

	cacheMutex.Lock()
	containerMap = newMap
	cacheExpiry = time.Now().Add(cacheDuration)
	cacheMutex.Unlock()
}

/*
GetPodByContainer resolves pod metadata
*/
func GetPodByContainer(containerID string) (string, string) {

	cs := getClient()
	if cs == nil {
		return "", ""
	}

	containerID = normalizeContainerID(containerID)

	if containerID == "" {
		return "", ""
	}

	cacheMutex.RLock()

	if time.Now().Before(cacheExpiry) {

		if meta, ok := containerMap[containerID]; ok {
			cacheMutex.RUnlock()
			return meta.Name, meta.Namespace
		}

		// fallback: short container ID match
		for id, meta := range containerMap {

			if strings.HasSuffix(id, containerID) {
				cacheMutex.RUnlock()
				return meta.Name, meta.Namespace
			}
		}
	}

	cacheMutex.RUnlock()

	// refresh cache if expired
	refreshCache(cs)

	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	if meta, ok := containerMap[containerID]; ok {
		return meta.Name, meta.Namespace
	}

	for id, meta := range containerMap {

		if strings.HasSuffix(id, containerID) {
			return meta.Name, meta.Namespace
		}
	}

	return "", ""
}

/*
Normalize container runtime ID formats
*/
func normalizeContainerID(id string) string {

	if id == "" {
		return ""
	}

	id = strings.TrimSpace(id)

	id = strings.TrimPrefix(id, "containerd://")
	id = strings.TrimPrefix(id, "docker://")
	id = strings.TrimPrefix(id, "cri-o://")

	id = strings.TrimPrefix(id, "cri-containerd-")
	id = strings.TrimPrefix(id, "docker-")

	id = strings.TrimSuffix(id, ".scope")

	return id
}
