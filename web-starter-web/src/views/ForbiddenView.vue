<template>
  <div class="forbidden-page">
    <el-result icon="warning" title="无权访问" sub-title="当前账号没有访问此功能所需的权限">
      <template #extra><el-button type="primary" @click="$router.push('/overview')">返回概览</el-button></template>
    </el-result>
  </div>
</template>

<style scoped>
.forbidden-page {
  display: grid;
  min-height: calc(100vh - 70px);
  place-items: center;
}
</style>
