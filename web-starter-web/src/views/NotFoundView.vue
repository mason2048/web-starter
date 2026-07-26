<template>
  <div class="page-content not-found-page">
    <el-result icon="warning" sub-title="请检查地址，或返回概览继续操作。">
      <template #title><h1 class="result-title">页面不存在</h1></template>
      <template #extra><el-button type="primary" @click="$router.push('/overview')">返回概览</el-button></template>
    </el-result>
  </div>
</template>

<style scoped>
.not-found-page {
  display: grid;
  min-height: 60vh;
  place-items: center;
}

.result-title {
  margin: 0;
  font-size: inherit;
  font-weight: inherit;
}
</style>
